package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Envelope encryption, per SPEC §17 ("Envelope encryption (AES-256-GCM) with a KEK
// from the environment, a KMS, or a file; key rotation supported").
//
// Every value gets a fresh 256-bit data-encryption key (DEK). The DEK is wrapped with
// the key-encryption key (KEK) and stored alongside the ciphertext. Rotating the KEK
// therefore means rewrapping DEKs, not re-encrypting payloads, and a Keyring can
// decrypt values written under previous KEKs while writing new ones under the active
// key.
//
// Wire format (version 1), stored as bytes or base64:
//
//	offset  size  field
//	     0     1  format version (0x01)
//	     1     1  length of the KEK id, in bytes
//	     2     n  KEK id (hex, derived from the key material)
//	   2+n    12  nonce for the DEK wrap
//	  14+n    48  wrapped DEK (32-byte key + 16-byte GCM tag)
//	  62+n    12  nonce for the payload
//	  74+n     -  payload ciphertext + 16-byte GCM tag
//
// The DEK wrap is authenticated with the header (version and KEK id) as additional
// data, so the recorded key identity cannot be swapped. The payload is authenticated
// with the caller's additional data, which callers should bind to the value's
// location — tenant id plus table plus column — so a ciphertext cannot be lifted from
// one row into another.
const (
	envelopeVersion = 0x01
	nonceSize       = 12
	dekSize         = 32
	gcmTagSize      = 16
	wrappedDEKSize  = dekSize + gcmTagSize
)

// ErrKeyUnknown is returned when a value was encrypted under a KEK the keyring does
// not hold. Operationally this means a key was rotated out before its data was
// rewrapped; the KEK id in the message tells the operator which key to restore.
var ErrKeyUnknown = errors.New("envelope was encrypted under a key this keyring does not hold")

// Keyring encrypts under one active KEK and decrypts under the active key or any
// retired key it still holds.
type Keyring struct {
	active   KEK
	byID     map[string]KEK
	randRead func([]byte) (int, error)
}

// NewKeyring builds a keyring. The first key is active — new values are encrypted
// under it. Any further keys are retired keys kept for decryption during a rotation.
func NewKeyring(active KEK, retired ...KEK) (*Keyring, error) {
	if active.IsZero() {
		return nil, ErrKEKNotConfigured
	}
	kr := &Keyring{
		active:   active,
		byID:     map[string]KEK{active.ID: active},
		randRead: rand.Read,
	}
	for _, k := range retired {
		if k.IsZero() {
			return nil, errors.New("retired key-encryption key is empty")
		}
		if _, dup := kr.byID[k.ID]; dup {
			return nil, fmt.Errorf("key-encryption key %s is listed twice", k.ID)
		}
		kr.byID[k.ID] = k
	}
	return kr, nil
}

// ActiveKeyID names the key new values are encrypted under. Surfaced on /healthz so
// operators can confirm a rotation reached every instance.
func (k *Keyring) ActiveKeyID() string { return k.active.ID }

// KeyIDs returns every key id the keyring can decrypt under, active first.
func (k *Keyring) KeyIDs() []string {
	ids := []string{k.active.ID}
	for id := range k.byID {
		if id != k.active.ID {
			ids = append(ids, id)
		}
	}
	return ids
}

// Encrypt seals plaintext under a fresh DEK wrapped by the active KEK. The aad is
// authenticated but not encrypted; pass the value's location so ciphertexts are not
// portable between rows.
func (k *Keyring) Encrypt(plaintext, aad []byte) ([]byte, error) {
	dek := make([]byte, dekSize)
	if _, err := io.ReadFull(readerFunc(k.randRead), dek); err != nil {
		return nil, fmt.Errorf("generating data key: %w", err)
	}
	defer zero(dek)

	header := make([]byte, 0, 2+len(k.active.ID))
	header = append(header, envelopeVersion, byte(len(k.active.ID)))
	header = append(header, k.active.ID...)

	dekNonce, err := k.nonce()
	if err != nil {
		return nil, err
	}
	kekGCM, err := newGCM(k.active.Bytes())
	if err != nil {
		return nil, fmt.Errorf("wrapping data key: %w", err)
	}
	wrapped := kekGCM.Seal(nil, dekNonce, dek, header)

	payloadNonce, err := k.nonce()
	if err != nil {
		return nil, err
	}
	dekGCM, err := newGCM(dek)
	if err != nil {
		return nil, fmt.Errorf("encrypting payload: %w", err)
	}
	ciphertext := dekGCM.Seal(nil, payloadNonce, plaintext, aad)

	out := make([]byte, 0, len(header)+nonceSize+len(wrapped)+nonceSize+len(ciphertext))
	out = append(out, header...)
	out = append(out, dekNonce...)
	out = append(out, wrapped...)
	out = append(out, payloadNonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// Decrypt opens an envelope. The aad must match the value passed to Encrypt.
func (k *Keyring) Decrypt(envelope, aad []byte) ([]byte, error) {
	if len(envelope) < 2 {
		return nil, errors.New("envelope is truncated")
	}
	if envelope[0] != envelopeVersion {
		return nil, fmt.Errorf("unsupported envelope version %d", envelope[0])
	}
	idLen := int(envelope[1])
	minLen := 2 + idLen + nonceSize + wrappedDEKSize + nonceSize + gcmTagSize
	if len(envelope) < minLen {
		return nil, errors.New("envelope is truncated")
	}

	header := envelope[:2+idLen]
	keyID := string(envelope[2 : 2+idLen])
	rest := envelope[2+idLen:]

	kek, ok := k.byID[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: key id %s", ErrKeyUnknown, keyID)
	}

	dekNonce, rest := rest[:nonceSize], rest[nonceSize:]
	wrapped, rest := rest[:wrappedDEKSize], rest[wrappedDEKSize:]
	payloadNonce, ciphertext := rest[:nonceSize], rest[nonceSize:]

	kekGCM, err := newGCM(kek.Bytes())
	if err != nil {
		return nil, fmt.Errorf("unwrapping data key: %w", err)
	}
	dek, err := kekGCM.Open(nil, dekNonce, wrapped, header)
	if err != nil {
		// Deliberately vague: distinguishing "wrong key" from "tampered ciphertext"
		// is an oracle.
		return nil, errors.New("envelope failed authentication")
	}
	defer zero(dek)

	dekGCM, err := newGCM(dek)
	if err != nil {
		return nil, fmt.Errorf("decrypting payload: %w", err)
	}
	plaintext, err := dekGCM.Open(nil, payloadNonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("envelope failed authentication")
	}
	return plaintext, nil
}

// EncryptString is Encrypt with base64 output, for storage in a text column.
func (k *Keyring) EncryptString(plaintext string, aad []byte) (string, error) {
	b, err := k.Encrypt([]byte(plaintext), aad)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}

// DecryptString is Decrypt over base64 input.
func (k *Keyring) DecryptString(encoded string, aad []byte) (string, error) {
	b, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("envelope is not valid base64: %w", err)
	}
	plaintext, err := k.Decrypt(b, aad)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// KeyIDOf reports which KEK an envelope was written under, without decrypting it.
// Rotation tooling uses this to find rows that still need rewrapping.
func KeyIDOf(envelope []byte) (string, error) {
	if len(envelope) < 2 || envelope[0] != envelopeVersion {
		return "", errors.New("not a recognised envelope")
	}
	idLen := int(envelope[1])
	if len(envelope) < 2+idLen {
		return "", errors.New("envelope is truncated")
	}
	return string(envelope[2 : 2+idLen]), nil
}

func (k *Keyring) nonce() ([]byte, error) {
	n := make([]byte, nonceSize)
	if _, err := io.ReadFull(readerFunc(k.randRead), n); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	return n, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	defer zero(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }
