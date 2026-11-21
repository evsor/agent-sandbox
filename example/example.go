// Package example holds the example sandbox config that sbx config copies into the user config dir.
package example

import "embed"

// FS holds the example's files at their paths in the config dir. Embedding skips dotfiles unless named or under an all: directory.
//
//go:embed Dockerfile .dockerignore all:image sandbox.toml
var FS embed.FS
