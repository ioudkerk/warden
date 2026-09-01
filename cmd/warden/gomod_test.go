package main

import (
	"os"
	"regexp"
	"testing"
)

// The minimum Go version is a decision recorded in ADR-0001 and restated in
// CONTRIBUTING.md: it is the floor for self-hosters building from source.
//
// It is also trivially easy to move by accident. Go computes the main module's
// directive as the maximum over every dependency's own, so a single `go get
// something@latest` that pulls a module built for a newer toolchain raises the floor
// for everyone — silently, with a passing build, on a machine that already has the
// newer toolchain. That is exactly how it drifted to 1.25 once.
//
// This test is the tripwire. If it fails, either restore the pins in go.mod or raise
// the floor deliberately: update this constant, ADR-0001 and CONTRIBUTING.md together.
const supportedGoVersion = "1.23.0"

func TestGoModHoldsTheSupportedFloor(t *testing.T) {
	raw, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}

	m := regexp.MustCompile(`(?m)^go (\S+)$`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("go.mod has no go directive")
	}
	if got := string(m[1]); got != supportedGoVersion {
		t.Errorf(
			"go.mod declares go %s, but the supported floor is %s.\n"+
				"A dependency was probably upgraded to one built for a newer toolchain. Either pin it back, "+
				"or raise the floor on purpose by updating this constant, docs/adr/0001-server-language.md "+
				"and CONTRIBUTING.md together.",
			got, supportedGoVersion)
	}
}
