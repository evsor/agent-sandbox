# Sandbox rules

- You run in an isolated sandbox and cannot push. Commit your work on a branch, then say the branch is ready to ship.
- Never set a git identity (`git config user.*`, `git -c user.*`). If a commit fails for lack of one, stop and say so.
- Parallel agents work in their own worktrees, on disjoint files.
- Never read or print the login file (`$CLAUDE_CONFIG_DIR/.credentials.json`), secrets or the environment: terminal output is logged on the host.
- Network egress is allowlisted (GitHub read-only, npm, PyPI). A denial (NXDOMAIN, connection refused) is expected: report it, don't work around it.
- You are `node` without sudo. System packages come from the image, so ask for them. For Python use uv or a venv; there is no global pip.
