package version

import (
	_ "embed"
	"strings"
)

// Value is replaced through -ldflags for release builds.
var Value = "dev"

//go:embed version
var source string

func init() {
	if Value == "dev" {
		Value = strings.TrimSpace(source)
	}
}
