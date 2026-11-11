# Security model

agent-sandbox runs AI agents in an msb microVM. The boundary is the VM, an egress allowlist and secret placeholders. Claude Code's permission rules are a second layer that agents can bypass. The sandbox is reasonably hardened against data exfiltration, access to the host and misuse of credentials.

* `sbx` and msb run as your host user. That user, the host OS, KVM, msb and `sbx` are in the trusted computing base. Keep msb and the host kernel updated.
* msb stores secret values and session logs as plain text in `~/.microsandbox`. Only your user can read them.
* The sandbox runs restricted, as the unprivileged user `node`, with no host mounts. Its data is on two disk volumes. **Never loop-mount a volume image on the host.** Agents control the file system on each volume.
* msb denies all traffic by default, including to your LAN, the host and cloud metadata. The sandbox can reach only the allowed hosts, on TCP port 443.
* Each allowed host widens what an agent can reach. With an attacker's credentials, an agent can send data through any allowed service. An `allow_ips` entry opens every site that has a valid certificate on that address.
* Your Claude login is on the sandbox's state volume, so an agent can read it. If you think that an attacker controls the sandbox, run `/logout` and revoke the session in claude.ai.
* Permission rules are advisory. The managed settings allow only their own rules, hooks and MCP servers, so a cloned repo cannot add its own. The root user owns these settings, so agents cannot change them. Bypass mode is off. Shell tricks can bypass the rules.

## Secrets

A secret's value stays on the host. The sandbox sees only a placeholder. msb puts the real value only in the named headers of requests to the `allow` hosts, and blocks the placeholder on other hosts, except the `passthrough` hosts.

```toml
[[secrets]]
name = "EXAMPLE_TOKEN"
allow = ["api.example.com"]
placeholder = "SBX-EXAMPLE-TOKEN-PLACEHOLDER"
header_fields = ["authorization"]
passthrough = ["api.anthropic.com"]
violation_action = "block-and-log"
```

`passthrough` lets the Claude API receive the placeholder unchanged. The placeholder appears in conversations, and it is not a secret.

## Shipping code

`sbx ship` fetches only git objects to the host, with git hooks disabled, and pushes them with the host credentials. It never checks out agent code.

## Policy check and `sbx verify`

`sbx` checks the config before each create, each image before msb loads it, and the running sandbox in `sbx verify`. The check is part of `sbx`, so a config change cannot weaken it. It requires the restricted VM, the two volumes, default deny with allows on port 443, secrets bound to hosts and headers, and the subscription login. A failure stops the operation.

`sbx verify` runs after each `sbx init` and `sbx rebuild`. It checks the guest, the network blocks, the placeholders and the host file modes. If a boundary check fails, it stops the sandbox.

`sbx rebuild` builds `main` as it is, direct commits included, so it does not enforce review. `sbx rebuild <sha>` also accepts each commit that a rebase merge or a fast-forward puts on `main`, though you reviewed only the final state. Your review must cover what the check does not, such as the Dockerfile packages.

## VS Code

A compromised VS Code server in the sandbox can act on your local VS Code. Keep VS Code updated and port forwarding off.

## Everything in the guest

Treat the guest as untrusted: agents, cloned repos, install scripts and agent memory. Memory and repo files persist through rebuilds, and they can carry injected instructions. Every capability that you grant becomes part of what an agent can do.
