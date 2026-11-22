// Package config holds the example config, embedded in sbx: sbx init writes it into the user config dir where a file is missing.
package config

import "embed"

// FS holds the example's files at their paths in a config dir. Embed skips dotfiles unless named or under all:, so .dockerignore is
// named and image/ uses all:, as docker copies its dotfiles too.
//
//go:embed Dockerfile .dockerignore all:image sandbox.toml
var FS embed.FS
