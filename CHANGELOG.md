# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.3.0] - 2026-11-07

### Added

- `sbx clone [<owner/name>...]` clones GitHub repos into the sandbox `/workspace`

## [0.2.0] - 2026-11-05

### Added

- `sbx rebuild [<sha>]` rebuilds the image from `origin/main`. Shows the changes from the last rebuild and recreates the sandbox with volumes untouched

## [0.1.0] - 2026-11-04

First release.

### Added

- `sbx init` checks the host, builds the image from `config/`, creates and starts the sandbox, writes its SSH files and verifies it. The command is immutable
- `sbx status`, `sbx stop` and `sbx verify`. A failed boundary check in `verify` stops the sandbox
- `sbx connect`, the SSH `ProxyCommand` for `ssh` and VS Code Remote-SSH
- `sbx rotate` updates every secret from its host variable
- `sbx ship` fetches an agent branch from the sandbox to the host
