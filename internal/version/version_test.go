package version

import (
	"regexp"
	"testing"
)

func TestValueIsSemanticVersion(t *testing.T) {
	if !regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`).MatchString(Value) {
		t.Fatalf("Value = %q, want semantic version", Value)
	}
}
