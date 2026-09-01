package conformance_test

import (
	"testing"

	"github.com/warden-project/warden/conformance"
	"github.com/warden-project/warden/conformance/reference"
)

// The corpus, executed against the reference evaluator. When the PDP lands in M2 it
// registers here too, and the two implementations must agree on every case.
func TestCorpusAgainstReferenceEvaluator(t *testing.T) {
	conformance.Run(t, "cases", reference.New())
}
