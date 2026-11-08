# Security model

The sandbox lets Claude Code agents work with little supervision while keeping what they can reach small. It is reasonably hardened against four things: prompt-injected agents sending data out, agents reaching the host, misuse of credentials, and drift in what the image is built from. It isn't meant to stop a determined attacker with a hypervisor exploit, or you merging a change that weakens it.

## The boundary

Three things together form the boundary. Everything else (Claude Code's permission rules, the managed `CLAUDE.md`) is a second layer that helps but can be bypassed.

1. **The VM.** The sandbox is a KVM microVM run by msb with `security = "restricted"`, as the unprivileged user `node`. It has no host mounts: its data lives on two disk volumes, `/workspace` and the Claude state directory, mounted `nosuid,nodev`. SSH is served by `sbx` on the host through the msb SDK, without agent forwarding.
2. **The egress allowlist.** All traffic is denied by default, in and out. The private, loopback, link-local, metadata and multicast ranges are denied before any allow, so the sandbox can't reach your LAN, the host or a cloud metadata service. It may reach only the hosts in `allow_domains` (and the narrow public ranges in `allow_ips`), on TCP port 443 only. Only allowlisted names resolve, which closes most DNS tunneling. TLS is intercepted with msb's CA so the gateway can check that the name a request is sent to matches the allowed name.
3. **A read-only, header-bound GitHub token.** The token is a fine-grained, read-only PAT for the repos you select. Its value stays on the host: `sbx` hands it to msb when the sandbox is created or the token rotated. The sandbox sees only a placeholder, in `GH_TOKEN`. msb's gateway puts the real value in place of the placeholder only in the `Authorization` header of requests to `github.com` and `api.github.com`. A request that carries the placeholder to any other host is blocked, except `api.anthropic.com`, which receives it unchanged: the placeholder ends up in conversations, Claude Code sends the whole conversation with every request, and the placeholder isn't secret.

The sandbox can't push: `sbx ship` pushes from the host with your credentials, moving only git objects and never checking out agent code.

## Your Claude login lives in the sandbox

You log in with `/login` and your subscription; API keys, auth tokens and key helpers are refused. The login is stored on the sandbox's state volume, so an agent in the sandbox can read it. A managed rule denies reading it, but rules are advisory. If you suspect a compromise, `/logout` and revoke the session in your claude.ai settings.

## Permission rules are advisory

Claude Code's settings live in `/etc/claude-code`, owned by root and read-only for `node`. Only the managed permission rules, hooks and MCP servers apply, so a cloned repo can't add its own; its skills, commands and `CLAUDE.md` still load. Bypass mode is disabled. Auto mode is allowed: its deny rules and explicit ask rules still apply. The rules ask before network tools, package installs and `git clone`, and deny pushes and publishes. Shell tricks can get around any of them, which is why the boundary above doesn't rely on them.

## The policy check

The policy check fails closed. It runs on `config/sandbox.toml` before every create or recreate, on each built image before it's loaded into msb, and on the running sandbox's config in `sbx verify`. It requires:

- no `${` anywhere (msb's CLI would fill it in from the host's environment);
- exactly the two disk volumes, `nosuid,nodev`, at `/workspace` and `/home/node/claude-state`, and no host paths;
- default deny in and out; strict name matching and TLS interception on; the five deny groups; no rule for the host gateway; allows only on TCP port 443, to a name (a wildcard needs at least two labels) or a narrow public address range; denies that name groups; no published ports;
- every secret bound to hosts and headers, with `api.anthropic.com` in its `passthrough`; no Anthropic API key, auth token or OAuth token as a secret or in the environment of the config or the image;
- `security = "restricted"` and the user `node`;
- in the image's `/etc/claude-code`: the subscription login forced, bypass mode disabled, the managed-only flags on, no API key or policy helper, no Anthropic credential or endpoint in `env`, settings drop-ins that may only repeat these values, and no entry that is a link, writable by group or others, or unreadable by `node`.

## Verify

`sbx verify` runs after every `sbx init` and `sbx rebuild`. It prints a PASS or FAIL row per check:

- in the sandbox: `node`'s ids and no-new-privileges, the managed settings owned by root and loaded, no agent credential in the environment, the volumes ext4 with `nosuid,nodev` and writable by `node`, the root disk's size;
- the policy check on the running sandbox's config;
- the network: an allowed host answers; other hosts, a raw IP, port 80, private, metadata and host addresses, domain fronting and unknown names are blocked;
- auth: any login is the subscription, `GH_TOKEN` is the placeholder, and the placeholder is blocked on a host it isn't bound to;
- on the host: the sandbox directory and volume files readable only by you, and the token's real value in no process environment in the sandbox.

A FAIL in a boundary check (the live policy check, the user ids, the volume mount options) also stops the sandbox.

## Risks you accept

- **Data out through allowed hosts.** An agent with an attacker's credentials can push to the attacker's GitHub repo, publish a package, or send data through the Claude API with another key. The ask and deny rules make this harder, but they are advisory.
- **Your repos are readable.** Anything in the sandbox can read the repos on the token's list. Keep the list short and the expiry close.
- **The login can be stolen.** See above.
- **`allow_ips`.** An address entry opens every site that address holds a valid certificate for, not one service.
- **Rebase merges.** `sbx rebuild <sha>` accepts each commit a rebase merge or fast-forward puts on `main`, though only the final state was reviewed. The policy check and the allowlist display still run.
- **You merge a weakening change.** Changes should reach `main` through a PR you review (`sbx` doesn't enforce this: it also accepts direct commits on `main`), and `sbx rebuild` builds only `main`. The security baseline is part of `sbx`, so a config change can't loosen it, but review must cover the rest, including everything the Dockerfile installs.
- **Package install scripts** from npm and PyPI run in the sandbox. The VM and the allowlist contain them.
- **Persisted state.** Agent memory and transcripts persist on the state volume and can carry injected instructions; files planted in repos persist on the workspace volume. Review PRs on GitHub.
- **Running agent code on the host.** Checking out an agent branch on your host and running its tooling runs agent code there. Review on GitHub, or run it in the sandbox.
- **VS Code.** A compromised VS Code server in the sandbox can act on your local VS Code. Keep VS Code updated, install few local extensions, and leave port forwarding off.
- **Session output on the host.** msb copies all terminal and exec output to its logs under `~/.microsandbox`, readable only by your user. Never print secrets.
- **The token on the host.** msb stores secret values in plain text in its sandbox config under `~/.microsandbox`, readable only by your user, and `msb inspect --format json` prints them.
- **Shared TLS CA.** msb's default CA is shared by all sandboxes on the host.
- **The VM.** A hypervisor escape defeats the boundary. Keep msb, its kernel library and the host kernel updated.
- **Prebuilt code in `sbx`.** The SDK embeds a prebuilt library, pinned by `go.sum` and bumped together with msb.

Never loop-mount a volume image on the host: agents control that filesystem.
