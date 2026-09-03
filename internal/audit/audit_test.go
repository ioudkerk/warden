package audit

import (
	"testing"
	"time"
)

// The canonical encoding must be unambiguous. Without length prefixes, an entry with
// action "a" and target "bc" would hash identically to one with action "ab" and
// target "c" — and an attacker able to choose those strings could substitute one
// entry for another without breaking the chain.
func TestCanonicalEncodingIsUnambiguous(t *testing.T) {
	at := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	a := canonical("aud_1", at, Entry{Action: "a", TargetType: "bc"}, nil, nil)
	b := canonical("aud_1", at, Entry{Action: "ab", TargetType: "c"}, nil, nil)
	if string(a) == string(b) {
		t.Fatal("two different entries produce the same canonical bytes; field boundaries are not encoded")
	}
}

func TestCanonicalEncodingIsStable(t *testing.T) {
	at := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	e := Entry{TenantID: "ten_a", Action: "role.granted", TargetID: "grn_1", Reason: "because"}

	first := canonical("aud_1", at, e, []byte(`{"a":1}`), nil)
	second := canonical("aud_1", at, e, []byte(`{"a":1}`), nil)
	if string(first) != string(second) {
		t.Fatal("the same entry encodes differently on two calls")
	}

	// A timezone difference must not change the encoding: the same instant is the
	// same instant, and an entry read back from Postgres in local time has to
	// recompute to the hash it was written with.
	local := at.In(time.FixedZone("elsewhere", 3*3600))
	if string(canonical("aud_1", local, e, []byte(`{"a":1}`), nil)) != string(first) {
		t.Fatal("the encoding depends on the timestamp's location, so a read-back entry cannot verify")
	}
}

// Every field must contribute to the hash. A field the hash ignores is a field an
// attacker can rewrite freely.
func TestEveryFieldAffectsTheHash(t *testing.T) {
	at := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	base := Entry{
		TenantID: "ten_a", ActorUserID: "usr_a", ActorClientID: "cli",
		ImpersonatorID: "usr_admin", Action: "role.granted", TargetType: "grant",
		TargetID: "grn_1", Reason: "r", IP: "10.0.0.1", UserAgent: "ua", RequestID: "req_1",
	}
	baseline := string(canonical("aud_1", at, base, []byte(`{"x":1}`), []byte(`{"y":2}`)))

	mutations := map[string]func(*Entry){
		"TenantID":       func(e *Entry) { e.TenantID = "ten_b" },
		"ActorUserID":    func(e *Entry) { e.ActorUserID = "usr_b" },
		"ActorClientID":  func(e *Entry) { e.ActorClientID = "other" },
		"ImpersonatorID": func(e *Entry) { e.ImpersonatorID = "usr_other" },
		"Action":         func(e *Entry) { e.Action = "role.revoked" },
		"TargetType":     func(e *Entry) { e.TargetType = "role" },
		"TargetID":       func(e *Entry) { e.TargetID = "grn_2" },
		"Reason":         func(e *Entry) { e.Reason = "different" },
		"IP":             func(e *Entry) { e.IP = "10.0.0.2" },
		"UserAgent":      func(e *Entry) { e.UserAgent = "other" },
		"RequestID":      func(e *Entry) { e.RequestID = "req_2" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			mutated := base
			mutate(&mutated)
			if string(canonical("aud_1", at, mutated, []byte(`{"x":1}`), []byte(`{"y":2}`))) == baseline {
				t.Errorf("%s does not affect the hash, so it can be rewritten undetected", name)
			}
		})
	}

	t.Run("id", func(t *testing.T) {
		if string(canonical("aud_2", at, base, []byte(`{"x":1}`), []byte(`{"y":2}`))) == baseline {
			t.Error("the entry id does not affect the hash")
		}
	})
	t.Run("occurred_at", func(t *testing.T) {
		later := at.Add(time.Second)
		if string(canonical("aud_1", later, base, []byte(`{"x":1}`), []byte(`{"y":2}`))) == baseline {
			t.Error("the timestamp does not affect the hash")
		}
	})
	t.Run("before", func(t *testing.T) {
		if string(canonical("aud_1", at, base, []byte(`{"x":9}`), []byte(`{"y":2}`))) == baseline {
			t.Error("the before state does not affect the hash")
		}
	})
	t.Run("after", func(t *testing.T) {
		if string(canonical("aud_1", at, base, []byte(`{"x":1}`), []byte(`{"y":9}`))) == baseline {
			t.Error("the after state does not affect the hash")
		}
	})
}

// The chain must depend on its predecessor, or each entry stands alone and a deletion
// leaves no trace.
func TestChainDependsOnThePredecessor(t *testing.T) {
	content := []byte("the same content")
	genesis := chainHash(nil, content)
	linked := chainHash(genesis, content)
	if string(genesis) == string(linked) {
		t.Fatal("the same content hashes identically regardless of its predecessor")
	}
	if len(genesis) != 32 {
		t.Fatalf("hash is %d bytes, want 32", len(genesis))
	}
}
