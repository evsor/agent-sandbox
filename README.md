# agent-sandbox

`sbx` runs Claude Code in one long-lived [microsandbox](https://github.com/superradcompany/microsandbox) (msb) microVM on your Linux host. You reach it from VS Code over Remote-SSH, and Claude runs several agents in parallel there on your Claude subscription. The VM reaches only an allowlist of hosts, holds no usable GitHub credential, and can't push: you move agent branches to GitHub from the host with `sbx ship`.

The sandbox is defined by the files in `config/`, and changes to it go through a PR, a merge and `sbx rebuild`. What the sandbox protects against, and what it doesn't, is in [SECURITY.md](SECURITY.md).

## Prerequisites

- Linux with KVM (`/dev/kvm` usable by your user).
- msb at the version of the microsandbox SDK in `go.mod` (`github.com/superradcompany/microsandbox/sdk/go`, v0.7.8 today). `sbx` refuses to run if the two differ.
- docker, git, ssh and `ssh-keygen`.
- `gh`, logged in (`gh auth login`), and a GitHub SSH key that can push to your repos: `sbx ship` pushes over SSH and opens the PR with `gh`.
- A Claude subscription (Pro, Max, Team or Enterprise). API keys are refused.
- A GitHub fine-grained personal access token, read-only:
  - *Only select repositories*: the repos the sandbox should clone, private ones included;
  - Contents: Read and Metadata: Read; optionally Pull requests: Read and Actions: Read; nothing with write access;
  - an expiry of 90 days or less. When it expires, export the new value as `GITHUB_PAT` and run `sbx rotate`.

## Install sbx

Releases are built and attested by `.github/workflows/release.yml` from `vX.Y.Z` tags on `main`. Download one, check its attestation, then install it where the SSH config runs it from (`~/.local/bin/sbx`):

```sh
gh release download vX.Y.Z -R evsor/agent-sandbox -p sbx
gh attestation verify sbx --repo evsor/agent-sandbox \
  --signer-workflow evsor/agent-sandbox/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z
install -D -m 0755 sbx ~/.local/bin/sbx
sbx --version
```

In a fork, use your own `owner/repo` in all three places. `sbx` never updates itself: repeat these steps for a new release.

## Setup

1. Fork or clone this repo. The clone on your host is your operator clone: `sbx init` and `sbx rebuild` run from it, and its `origin` is the repo whose `main` the sandbox is built from.
2. Set your git identity in `config/image/etc/gitconfig`, under `[user]`. The file is public, so use your GitHub noreply address. A fork must replace any identity already there.

   ```ini
   [user]
   	name = Your Name
   	email = 12345+you@users.noreply.github.com
   	useConfigOnly = true
   ```

   Until it's set, git in the sandbox refuses to commit. Merge this change to `main` first: `sbx rebuild` builds only merged `main`.
3. Export the token: `export GITHUB_PAT=<token>`, in the shell you run `sbx init`, `sbx rebuild`, `sbx rotate` and `sbx verify` from. Load it however you like (a password manager, `secret-tool`, …); `sbx` never prompts for it or stores it; msb keeps it in its sandbox config on the host (see SECURITY.md).
4. From the operator clone, run `sbx init`. It checks the host, writes its SSH files under `~/.local/state/agent-sandbox/ssh/`, builds the image from `config/`, runs the policy check on the config and the image, creates and starts the sandbox, and runs `sbx verify`. It is safe to re-run.
5. Add the line `sbx init` prints at the top of `~/.ssh/config`, once (after a `Host` line it would apply only to that host):

   ```text
   Include ~/.local/state/agent-sandbox/ssh/config
   ```

   `ssh claude-sandbox` now reaches the sandbox as `node`. `sbx` never reads or edits `~/.ssh`.
6. In VS Code, install Remote-SSH and set, in your user settings:

   ```json
   "remote.autoForwardPorts": false,
   "remote.SSH.defaultExtensions": ["Anthropic.claude-code"]
   ```

   Leave `remote.SSH.localServerDownload` at its default, `auto`: the sandbox can't download the VS Code server or extensions, so VS Code fetches them on the host and copies them over.
7. Clone your repos into the sandbox: `sbx clone <owner/name>...` clones each into `/workspace/<name>` through the read-only token.
8. In VS Code, connect to the host `claude-sandbox` and open a folder under `/workspace`.
9. Run `/login` in Claude (the panel or a terminal in the sandbox): open the URL on your host and paste the code back. The login lives on the sandbox's state volume and survives rebuilds.

## Daily use

- Open VS Code on `claude-sandbox`. A stopped sandbox starts when you connect.
- A new repo: `sbx clone` from a host checkout of it clones its `origin`, or `sbx clone <owner/name>` from anywhere. A private repo must be on the token's repository list. An existing checkout is left untouched.
- Talk to Claude. It runs parallel work as subagents in their own git worktrees, and you can hand off a task with `claude --bg "<task>"` (list them with `claude agents`). Background sessions keep running after you close VS Code.
- Ship work with `sbx ship` (or `sbx ship <repo> <branch>`). It lists the branches in `/workspace` with commits that `origin` doesn't have, fetches the one you pick into a bare repo on the host, shows its log against the default branch and asks before pushing it to GitHub with your credentials and opening a PR with `gh pr create --fill`. On a repo's first ship it asks which GitHub repo to push to, and remembers. It refuses the default branch. Shipping a branch that already has a PR pushes the new commits, then `gh` prints the existing PR and `sbx` exits 1.
- `sbx status` shows the sandbox's state, image, volume usage, login and background sessions, and whether a rebuild is pending. After your first `sbx rebuild`, it says `pending (run sbx rebuild)` when `origin/main`, as of the operator clone's last `git fetch`, has moved since.
- `sbx rebuild` rebuilds the image from `origin/main` in a clean worktree and recreates the sandbox; the volumes (repos, login, agent state) are kept. It refuses an operator clone with uncommitted changes. Before recreating, it shows the allowlist and secret changes since the last rebuild and the background sessions it will stop, and asks once. It ends with `sbx verify`. On `VERIFY FAILED`, it prints the last good commit: run `sbx rebuild <sha>` with it. Only a merge or a direct commit on `main` is accepted, not a commit from inside a merged branch.
- `sbx stop` stops the sandbox; `sbx verify` re-runs the checks at any time.

## Changing things

Edit, open a PR, merge, then run `sbx rebuild` from the operator clone. In the sandbox, Claude can make the change and you ship it like any other branch.

| To change | Edit |
|---|---|
| Packages and tools | `config/Dockerfile` |
| Claude Code rules and settings | `config/image/etc/claude-code/managed-settings.json` |
| Instructions for every session | `config/image/etc/claude-code/CLAUDE.md` |
| Git defaults and identity | `config/image/etc/gitconfig` |
| CPUs and memory | `cpus`, `memory_mib` in `config/sandbox.toml` |
| Hosts the sandbox may reach | `allow_domains` in `config/sandbox.toml` |
| Secrets | `[[secrets]]` in `config/sandbox.toml` |

The security baseline (the VM settings, the network deny groups, port 443 only, the volumes, bypass mode off, subscription login only) is checked by `sbx`'s policy check, so a config change can't loosen it: that takes a change to `sbx` and a new release.

**Allowlist.** Add a host to `allow_domains`, with a comment saying why. `.example.com` also matches its subdomains. Use `allow_ips` only for a service that has no usable name. It takes public addresses or ranges no wider than /16 (IPv4) or /32 (IPv6), on port 443 only. An address entry doesn't make a name resolve, so only a client that can connect to the address under the right name works (for example `curl --resolve name:443:address`), and it opens every site that address holds a valid certificate for.

**Secrets.** A secret's value stays on the host and never enters the sandbox. The sandbox sees only a placeholder (for `GITHUB_PAT`, `GH_TOKEN` holds `SBX-GITHUB-PAT-PLACEHOLDER`). msb's network gateway swaps the placeholder for the real value in the `header_fields` headers of requests to the `allow` hosts, and blocks any other request that holds it.

Every secret needs `passthrough = ["api.anthropic.com"]`, and the policy check refuses one without it. The placeholder ends up in conversations (an agent runs `env` or reads `sandbox.toml`), and Claude Code sends the whole conversation with every request. If the gateway blocked those requests, the session would stop for good. The placeholder isn't secret, so sending it to the Claude API unchanged leaks nothing.

To add a secret:
1. Copy the `GITHUB_PAT` block in `config/sandbox.toml` and change `name` (the host variable that holds the value), `allow` (the hosts that get the real value), `placeholder` (any string without `$`) and `header_fields` (the header the service reads its token from).
2. Add its hosts to `allow_domains`.
3. If a tool in the sandbox reads its token from a variable, add an `env` entry holding the placeholder, like `GH_TOKEN`.
4. Merge, export the variable on the host, and run `sbx rebuild`.

**Pin bumps.** Dependabot opens PRs for the base image digest in `config/Dockerfile`, the GitHub Actions and the Go modules. Bump these by hand: the Dockerfile's `# syntax=` parser and the uv image (by digest), the gh release tarball (URL and sha256 from the release's checksums file), `CLAUDE_CODE_VERSION`, and the microsandbox SDK in `go.mod` together with msb (a new SDK needs a new `sbx` release).

**A new sbx.** A merged change under `cmd/` or `internal/` reaches your host only through a release:
1. Merge a PR that moves `CHANGELOG.md`'s `[Unreleased]` entries under `## [X.Y.Z] - <date>`.
2. Tag that merge on `main` and push the tag: `git tag vX.Y.Z <sha>` and `git push origin vX.Y.Z`. The release workflow builds and attests `sbx`; its release notes list the PRs merged since the previous release.
3. Install it as in [Install sbx](#install-sbx).

## Troubleshooting

- **A host is blocked.** Names outside the allowlist don't resolve, so tools report NXDOMAIN or "could not resolve host". Add the host to `allow_domains` in `config/sandbox.toml`, merge, and `sbx rebuild`.
- **A Claude session stops answering after a few minutes of retries.** A secret's placeholder is probably being blocked on its way to the Claude API. Check msb's runtime log on the host:

  ```sh
  grep 'placeholder detected' ~/.microsandbox/sandboxes/claude-sandbox/logs/runtime.log*
  ```

  If it matches, make sure every `[[secrets]]` entry has `passthrough = ["api.anthropic.com"]`, then merge and `sbx rebuild`. The session works again after the rebuild.
- **Login expired.** If Claude asks you to log in again, run `/login` in the sandbox.
- **An SSH session or VS Code hangs.** The keepalives (`ServerAliveInterval`, `ServerAliveCountMax`) in `~/.local/state/agent-sandbox/ssh/config` end a dead connection. Make sure the `Include` line is at the top of `~/.ssh/config`, and re-run `sbx init` to rewrite the file if it was edited.
- **Background sessions after a rebuild.** A rebuild or restart stops them. `claude agents` lists them; `claude respawn <id>` (or `claude respawn --all`) restarts them.

## Incident response

If you suspect the sandbox or an agent is compromised:
1. `sbx stop`.
2. Log out: `/logout` in the sandbox, then revoke the session in your claude.ai settings.
3. Revoke the GitHub token in your GitHub settings.
4. Review the recent PRs and the commits on `main`, especially changes under `config/`, `cmd/` and `internal/`, before you rebuild or release.

## Rare operations (msb)

These use msb directly; `claude-sandbox`, `claude-workspace` and `claude-state` are the names in `config/sandbox.toml`.

- Session output msb captured: `msb logs claude-sandbox` (`--tail <n>`, `-f` to follow). msb's own log is `~/.microsandbox/sandboxes/claude-sandbox/logs/runtime.log`.
- Remove the sandbox, keeping the volumes: `msb rm -f claude-sandbox`. `sbx init` creates it again.
- Remove the volumes, after the sandbox: `msb volume rm claude-workspace claude-state`. This deletes your repos, any unshipped work, the login and the agent state.
- Remove old images: each rebuild leaves one in msb and one in docker. `msb image prune` removes msb's copies that no sandbox uses; list docker's with `docker image ls claude-code-msb` and remove them with `docker image rm claude-code-msb:<tag>`.

Never loop-mount a volume image (`~/.microsandbox/volumes/*/disk.raw`) on the host: agents control that filesystem, and a crafted one can attack the host kernel.
