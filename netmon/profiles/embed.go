// Package profiles embeds the built-in vendor profiles into the binaries.
package profiles

import "embed"

// FS holds every *.yaml profile in this directory.
//
//go:embed *.yaml
var FS embed.FS
