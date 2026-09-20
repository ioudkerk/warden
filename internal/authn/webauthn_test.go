package authn_test

import (
	"context"
	"errors"
	"testing"

	"github.com/warden-project/warden/internal/authn"
	"github.com/warden-project/warden/internal/authn/authntest"
)

// WebAuthn, against a virtual authenticator that signs for real.
//
// The tests below are about the three things a relying party has to get right, and each of
// them fails silently if it is wrong — the flow still works, and the property it was meant
// to provide is simply absent:
//
//   - the signature is checked against the key that was registered;
//   - the assertion is bound to *this* origin, which is what a phishing page cannot forge;
//   - the challenge is spent, so a captured assertion cannot be replayed.

const (
	testRPID   = "warden.test"
	testOrigin = "https://warden.test"
)

// TestASecurityKeyEnrolsAndThenSignsIn is the happy path, end to end.
func TestASecurityKeyEnrolsAndThenSignsIn(t *testing.T) {
	f := newMFAFixture(t)
	key := authntest.New(t)
	ctx := context.Background()

	// Enrolment.
	challenge, err := f.authn.BeginWebAuthnRegistration(ctx, f.tenantID, f.userID, "maria@acme.test")
	if err != nil {
		t.Fatalf("beginning registration: %v", err)
	}
	response := key.Register(t, authntest.ChallengeFrom(t, challenge.Options), testOrigin, testRPID)
	if registerErr := f.authn.FinishWebAuthnRegistration(
		ctx, f.tenantID, f.userID, challenge.SessionID, "The key on my keyring", response); registerErr != nil {
		t.Fatalf("finishing registration: %v", registerErr)
	}

	// It counts as a second factor now.
	has, err := f.authn.HasSecondFactor(ctx, f.tenantID, f.userID)
	if err != nil {
		t.Fatalf("checking: %v", err)
	}
	if !has {
		t.Fatal("a registered security key does not count as a second factor")
	}

	// And it signs in.
	login, err := f.authn.BeginWebAuthnLogin(ctx, f.tenantID, f.userID)
	if err != nil {
		t.Fatalf("beginning login: %v", err)
	}
	assertion := key.Assert(t, authntest.ChallengeFrom(t, login.Options), testOrigin, testRPID)
	if err := f.authn.FinishWebAuthnLogin(
		ctx, f.tenantID, f.userID, login.SessionID, assertion); err != nil {
		t.Fatalf("finishing login: %v", err)
	}
}

// TestAnAssertionFromAnotherOriginIsRefused is the property WebAuthn exists for.
//
// This is what a phishing page produces. Somebody types their password into a convincing
// copy of the login page, the copy relays the challenge to their real security key, and the
// key answers — but it signs over the origin the *browser* is talking to, which is the
// attacker's. A server that did not check it would accept the relayed assertion and the
// second factor would be worth exactly as much as the six digits it replaced.
func TestAnAssertionFromAnotherOriginIsRefused(t *testing.T) {
	f := newMFAFixture(t)
	key := f.enrolKey(t)
	ctx := context.Background()

	login, err := f.authn.BeginWebAuthnLogin(ctx, f.tenantID, f.userID)
	if err != nil {
		t.Fatalf("beginning login: %v", err)
	}

	// The same key, the same challenge, a different origin.
	assertion := key.Assert(t, authntest.ChallengeFrom(t, login.Options), "https://warden-login.test", testRPID)

	err = f.authn.FinishWebAuthnLogin(ctx, f.tenantID, f.userID, login.SessionID, assertion)
	if err == nil {
		t.Fatal("an assertion signed for another origin was accepted; a phishing page could " +
			"relay a real key and this factor would stop nothing")
	}
	if !errors.Is(err, authn.ErrInvalidSecondFactor) {
		t.Fatalf("= %v; want the generic refusal", err)
	}
}

// TestAnAssertionForAnotherRelyingPartyIsRefused is the same defence one layer down.
//
// The relying-party id is hashed into the authenticator data, so a key that answered for a
// different domain produces a hash the server will not recognise — even if the origin in the
// client data were forged to look right.
func TestAnAssertionForAnotherRelyingPartyIsRefused(t *testing.T) {
	f := newMFAFixture(t)
	key := f.enrolKey(t)
	ctx := context.Background()

	login, err := f.authn.BeginWebAuthnLogin(ctx, f.tenantID, f.userID)
	if err != nil {
		t.Fatalf("beginning login: %v", err)
	}
	assertion := key.Assert(t, authntest.ChallengeFrom(t, login.Options), testOrigin, "evil.test")

	if err := f.authn.FinishWebAuthnLogin(
		ctx, f.tenantID, f.userID, login.SessionID, assertion); err == nil {
		t.Fatal("an assertion carrying another relying party's hash was accepted")
	}
}

// TestAChallengeIsSpent. Without this, an assertion captured once is an assertion that works
// again — and the whole point of a challenge is that it does not.
func TestAChallengeIsSpent(t *testing.T) {
	f := newMFAFixture(t)
	key := f.enrolKey(t)
	ctx := context.Background()

	login, err := f.authn.BeginWebAuthnLogin(ctx, f.tenantID, f.userID)
	if err != nil {
		t.Fatalf("beginning login: %v", err)
	}
	assertion := key.Assert(t, authntest.ChallengeFrom(t, login.Options), testOrigin, testRPID)

	if firstErr := f.authn.FinishWebAuthnLogin(
		ctx, f.tenantID, f.userID, login.SessionID, assertion); firstErr != nil {
		t.Fatalf("the first use: %v", firstErr)
	}

	// The second attempt must fail *because the challenge is gone*, which is a different
	// error from the signature counter noticing. Asserting only "it failed" would pass
	// with the challenge left in the cache — the first version of this test did, and was
	// testing the clone detector rather than the thing it named.
	err = f.authn.FinishWebAuthnLogin(ctx, f.tenantID, f.userID, login.SessionID, assertion)
	if !errors.Is(err, authn.ErrInvalidSecondFactor) {
		t.Fatalf("replaying an assertion = %v; want the challenge to be gone. A challenge "+
			"that survives its answer is a challenge that can be answered again", err)
	}
}

// TestAWrongSignatureIsRefused. The obvious one, and the one whose absence would make every
// other test here meaningless: if the signature is not really checked, anybody's assertion
// works.
func TestAWrongSignatureIsRefused(t *testing.T) {
	f := newMFAFixture(t)
	f.enrolKey(t)
	ctx := context.Background()

	// A different key entirely, claiming the enrolled credential's id.
	impostor := authntest.New(t)
	login, err := f.authn.BeginWebAuthnLogin(ctx, f.tenantID, f.userID)
	if err != nil {
		t.Fatalf("beginning login: %v", err)
	}
	assertion := impostor.Assert(t, authntest.ChallengeFrom(t, login.Options), testOrigin, testRPID)

	if err := f.authn.FinishWebAuthnLogin(
		ctx, f.tenantID, f.userID, login.SessionID, assertion); err == nil {
		t.Fatal("an assertion signed by a different key was accepted")
	}
}

// TestACounterThatGoesBackwardsIsRefused is WebAuthn §6.1.1's clone detection.
//
// A real authenticator's signature counter only increases. Two of them answering for one
// credential — which is what a copied key looks like — makes it go backwards, and that is
// the only evidence a relying party ever gets that a key has been duplicated.
func TestACounterThatGoesBackwardsIsRefused(t *testing.T) {
	f := newMFAFixture(t)
	key := f.enrolKey(t)
	ctx := context.Background()

	// One good login, which advances the stored counter.
	login, err := f.authn.BeginWebAuthnLogin(ctx, f.tenantID, f.userID)
	if err != nil {
		t.Fatalf("beginning login: %v", err)
	}
	if firstErr := f.authn.FinishWebAuthnLogin(ctx, f.tenantID, f.userID, login.SessionID,
		key.Assert(t, authntest.ChallengeFrom(t, login.Options), testOrigin, testRPID)); firstErr != nil {
		t.Fatalf("the first login: %v", firstErr)
	}

	// Now the clone answers, with the counter it had when it was copied.
	login, err = f.authn.BeginWebAuthnLogin(ctx, f.tenantID, f.userID)
	if err != nil {
		t.Fatalf("beginning login: %v", err)
	}
	cloned := key.AssertWithCount(t, authntest.ChallengeFrom(t, login.Options), testOrigin, testRPID, 1)

	err = f.authn.FinishWebAuthnLogin(ctx, f.tenantID, f.userID, login.SessionID, cloned)
	if !errors.Is(err, authn.ErrCredentialCloned) {
		t.Fatalf("= %v; want the clone refusal. A counter that went backwards is the only "+
			"evidence there is that a key has been copied", err)
	}
}

// TestAChallengeBelongsToTheUserItWasIssuedFor. The identifier is random, so this is not a
// likely attack — but the check costs a comparison, and without it a challenge identifier
// leaked from one login could be answered in another's.
func TestAChallengeBelongsToTheUserItWasIssuedFor(t *testing.T) {
	f := newMFAFixture(t)
	key := f.enrolKey(t)
	ctx := context.Background()

	login, err := f.authn.BeginWebAuthnLogin(ctx, f.tenantID, f.userID)
	if err != nil {
		t.Fatalf("beginning login: %v", err)
	}
	assertion := key.Assert(t, authntest.ChallengeFrom(t, login.Options), testOrigin, testRPID)

	if err := f.authn.FinishWebAuthnLogin(
		ctx, f.tenantID, "usr_somebody_else", login.SessionID, assertion); err == nil {
		t.Fatal("a challenge issued for one user was answered for another")
	}
}

// TestTheRelyingPartyComesFromTheIssuer. Getting this wrong is the most common way a
// WebAuthn deployment fails, and it fails only in a real browser: the id is a domain, the
// origin carries the scheme and the port.
func TestTheRelyingPartyComesFromTheIssuer(t *testing.T) {
	for issuer, want := range map[string]authn.WebAuthnOptions{
		"https://warden.acme.com": {
			RPID: "warden.acme.com", Origins: []string{"https://warden.acme.com"},
		},
		"https://warden.acme.com:8443": {
			RPID: "warden.acme.com", Origins: []string{"https://warden.acme.com:8443"},
		},
		"http://localhost:8080": {
			RPID: "localhost", Origins: []string{"http://localhost:8080"},
		},
	} {
		t.Run(issuer, func(t *testing.T) {
			got, err := authn.WebAuthnOptionsFromIssuer(issuer, "")
			if err != nil {
				t.Fatalf("%v", err)
			}
			if got.RPID != want.RPID {
				t.Errorf("RPID = %q, want %q — a credential registered against the wrong "+
					"one cannot be used at all", got.RPID, want.RPID)
			}
			if len(got.Origins) != 1 || got.Origins[0] != want.Origins[0] {
				t.Errorf("origins = %v, want %v", got.Origins, want.Origins)
			}
		})
	}
}
