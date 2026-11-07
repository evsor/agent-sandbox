# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.3.1] - 2026-11-07

### Added

- `passthrough` in a `[[secrets]]` entry of `sandbox.toml` lists hosts that may receive the secret placeholder. Every secret must include `api.anthropic.com` or the conversation will be blocked
- Document how secrets work and how to add one, in `sandbox.toml`

### Changed

- Auto mode is allowed, with the ask and deny rules still applied

### Fixed

- Claude Code sessions no longer stop once the secret's placeholder is in the conversation

## [0.3.0] - 2026-11-07

### Added

- `sbx clone [<owner/name>...]` clones GitHub repos into the sandbox `/workspace`

## [0.2.0] - 2026-11-05

### Added

- `sbx rebuild [<sha>]` rebuilds the image from `origin/main`. Shows the changes from the last rebuild and recreates the sandbox with volumes untouched

## [0.1.0] - 2026-11-04

First release.

### Added

- `sbx init` checks the host, builds the image from `config/`, creates and starts the sandbox, writes its SSH files and verifies it. The command is idempotent
- `sbx status`, `sbx stop` and `sbx verify`. A failed boundary check in `verify` stops the sandbox
- `sbx connect`, the SSH `ProxyCommand` for `ssh` and VS Code Remote-SSH
- `sbx rotate` updates every secret from its host variable
- `sbx ship` fetches an agent branch from the sandbox to the host
