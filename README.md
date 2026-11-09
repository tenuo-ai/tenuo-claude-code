# Tenuo for Claude Code

[![PyPI](https://img.shields.io/pypi/v/tenuo-claude-code)](https://pypi.org/project/tenuo-claude-code/)
[![Python](https://img.shields.io/pypi/pyversions/tenuo-claude-code)](https://pypi.org/project/tenuo-claude-code/)
[![CI](https://github.com/tenuo-ai/tenuo-claude-code/actions/workflows/ci.yml/badge.svg)](https://github.com/tenuo-ai/tenuo-claude-code/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**Task-scoped authorization for Claude Code.**

Give Claude Code access to your codebase and tools without giving it access to everything. Tenuo constrains what Claude can read, execute, fetch, and invoke before each action runs. You get signed evidence of what was allowed or denied—a tamper-proof audit trail.

Tenuo works alongside Claude Code permissions. It adds a signed, expiring authority token that stays enforced even when permission prompts are bypassed, across MCP calls and subagents.

## Why Tenuo?

Claude Code permissions prompt the user; Tenuo checks the **model's action** at the authorizer boundary. The difference matters:

| | Claude Code permissions | Tenuo warrant |
|---|---|---|
| **Trigger** | User prompt when Claude asks for access | Automatic check before every tool call |
| **Scope** | Tool name only | Tool name + argument values |
| **Bypass** | Prompt can be skipped | Cannot be disabled by the user |
| **Evidence** | Optional hook logs | Signed, tamper-proof receipts |
| **Revocation** | Edit rules (active sessions may keep access) | Instant fleet-wide revocation (Cloud) |
| **Enforcement** | Claude Code settings UI | PreToolUse hook + MCP proxy + authorizer |
| **Span** | Single session | Persists across MCP calls and subagents |

Tenuo doesn't replace Claude Code permissions—it adds a cryptographic gate that works regardless of why the model tried the call: prompt injection, hallucination, poisoned tool output, or direct user request.

## What It Looks Like

After setup, this is what you see:

```
tenuo-claude audit --verify

DENY   Read /etc/passwd                constraint not satisfied
       path outside workspace (subpath:/home/user/project)

ALLOW  Read /home/user/project/main.py  constraint satisfied
DENY   Bash rm -rf /                    command not permitted
       'rm' not in allowlist [ls,pwd,cat,grep]

3 signed receipts verified:
  Ed25519 signatures valid
  Hash chain unbroken
  Constraints replayed and satisfied
```

Each decision is:
- **Signed** with Ed25519 (cryptographic proof)
- **Hash-chained** (tampering is detected)
- **Constraint-replayed** (warrant terms verified at audit time)
- **Cloud-synced** (if configured, sent to tenant for fleet audit)

## Quickstart

One command to try it:

```bash
uv tool install tenuo-claude-code
tenuo-claude bootstrap --native --pack filesystem-dev
claude
```

That's it. `bootstrap` with `--pack filesystem-dev` generates a starter policy (read and edit your project, keep Tenuo's keys and hook wiring out of reach, a minimal shell), starts the authorizer, and runs a self-test. Open Claude Code, try something in-scope (it works) and out-of-scope (it's denied). Then:

```bash
tenuo-claude audit --verify
```

to see the signed decision log.

### What the quickstart does

1. **`--pack filesystem-dev`** generates a preconfigured policy:
   - Read, edit and search files in your project directory (paths resolved, symlinks followed)
   - Never read or change Tenuo's own files: `.state/` keys, `tenuo.yaml`, `.mcp.json`, `.claude/settings*.json`
   - Run only `ls` and `pwd` in the shell; add your test and build commands to `Bash:`. The shell check covers the command name, not its paths, so list only commands you'd allow on any path
   - Deny everything else by default
   - Start in `mode: dry-run` (log, don't block)

2. **`--native`** uses the native authorizer binary (no Docker needed)

3. **`bootstrap`** mints a session warrant, wires the PreToolUse hook, starts the authorizer, and runs a test

4. **`claude`** opens Claude Code. The authorizer is now active; every tool call is checked.

After you see it working, edit `tenuo.yaml` to fit your project, switch to `mode: enforce`, and run:

```bash
tenuo-claude refresh
```

**Available policy packs:**
- `filesystem-dev` — Read/write project files, minimal shell (default)
- `github-mcp` — GitHub MCP server, constrained API queries
- `http-api-safe` — WebFetch with SSRF protection and domain allowlists

Browse more: [examples/policies/](examples/policies/).

**For Cloud mode** (org root, revocation, human approval):

```bash
tenuo-claude bootstrap --native --pack filesystem-dev --cloud
```

Then follow the Cloud setup prompts. [Details: Cloud mode](#cloud-mode).

## How It Works

You define what Claude can do in `tenuo.yaml`:

```yaml
name: my-project
sandbox: ./workspace

enforce:
  Read:  "subpath:{sandbox}"              # Read only project files
  Bash:  "shlex:ls,pwd,cat,grep"          # Only these commands
  WebFetch:
    domains: ["api.github.com"]            # Only this domain
    
subagents:
  analyst:
    tools: [Read, Grep]                    # Analyst: read-only

default: deny                               # Block everything else
mode: dry-run                               # Log, don't block (switch to 'enforce' later)
```

Tenuo compiles this into a signed, expiring **warrant** (a capability token). Every Claude action is checked against the warrant before it runs:

- **File reads** — constrained by `subpath` (can't escape the directory)
- **Shell commands** — constrained by `shlex` (only allowlisted verbs, no pipes/chaining)
- **Web fetches** — constrained by domain, SSRF-safe
- **MCP calls** — constrained by tool name and per-argument rules
- **Subagent spawns** — gated to declared roles, each runs with narrower authority

The same boundary applies no matter why the model tried the call.

### Constraints

- **`subpath:DIR`** — path must resolve inside DIR (symlink-safe)
- **`shlex:verb,verb`** — command executable must be in list; pipes/chaining/subshells denied
- **`domains:[host]`** — URL domain must match (with SSRF/encoded-IP hardening)
- **`oneof:a,b`** · **`exact:v`** · **`pattern:glob`** · **`regex:re`** · **`range:min,max`** — argument must satisfy the constraint
- See [Policy](#policy) for the full list and examples

## Day-to-Day Commands

```bash
tenuo-claude up              # Start the authorizer
tenuo-claude refresh         # Recompile after editing tenuo.yaml
tenuo-claude audit --verify  # Review and verify the decision log
tenuo-claude down            # Stop the authorizer
```

Full command reference: [Commands](#commands).

## Cloud Mode

For organizations: org-root warrants, instant fleet revocation, human approval gates, and a central audit trail.

```bash
tenuo-claude bootstrap --native --pack filesystem-dev --cloud
```

Setup takes ~2 minutes (Cloud tenant, runtime credentials, policy trigger). After that, Tenuo issues warrants signed by your org root, revokes them fleet-wide in ~30s, and sends signed receipts to your tenant for compliance audit.

Human approval is optional: gate any tool to require sign-off (Slack, Telegram, console, etc.) from a named approver.

See [Cloud mode](#cloud-mode) for details.

## What's in Scope

Tenuo governs **model-invoked tool calls** on the PreToolUse path:
- **Read**, **Write**, **Glob**, **Edit** — file access
- **Bash**, **Monitor**, **PowerShell** — command execution
- **WebFetch** — HTTP requests
- **MCP tools** — downstream server calls (via proxy)
- **Agent** — subagent spawning

It does **not** govern:
- The `!` TUI shell (operator command, not model-invoked)
- Approved operator actions outside the PreToolUse boundary

## Fail-Closed Design

- Missing or broken `tenuo.yaml` denies every governed call until restored
- Private keys under `.state/` are owner-only (`0600`)
- A broken receipt sink surfaces loudly (not silent data loss)
- Cloud-disconnected nodes fall back to local policy (no open bypass)

---

## Policy

`tenuo.yaml` drives the whole system: warrant, authorizer, hooks, MCP proxy.

```yaml
name: acme-backend
sandbox: ./workspace        # a directory; {sandbox} expands to its absolute path
ttl_seconds: 3600           # optional: session warrant lifetime (default 3600 = 1h)
mode: enforce               # block out-of-scope calls; 'dry-run' = log only

enforce:
  Read:  "subpath:{sandbox}"
  Write: "subpath:{sandbox}"
  Bash:  "shlex:ls,pwd,echo,cat,grep"
  WebFetch:
    domains: ["api.github.com", "*.githubusercontent.com"]
  
allow:                      # permitted, unconstrained (logged)
  - TodoRead

default: deny               # anything unlisted is denied (recommended, fail-closed)

subagents:                  # optional: each role runs under a narrower warrant
  analyst:
    tools: [Read, Grep, Glob]

mcp:                        # optional: govern a downstream MCP server's tools
  downstream: ./your_mcp_server.py
  enforce:
    read_file: "subpath:{sandbox}"
    run_query:
      arg: sql
      constraint: "regex:^SELECT "
```

### Constraints

| Constraint | Applies to | Checks |
|------------|------------|--------|
| `subpath:DIR` | Read, Write, Edit, Glob, Grep | Path resolves inside DIR (symlink-safe) |
| `shlex:a,b,c` | Bash, Monitor, PowerShell | Executable is one of `a,b,c`; pipes/chaining/subshells denied |
| `domains:[list]` | WebFetch | URL domain matches allowlist; SSRF/encoded-IP hardening built-in |
| `oneof:a,b` | any tool | Value is in set |
| `notoneof:a,b` | any tool | Value not in set |
| `exact:v` | any tool | Value equals exactly |
| `pattern:glob` | any tool | Value glob-matches |
| `regex:re` | any tool | Value regex-matches |
| `range:min,max` | any tool | Value in numeric range |
| `urlpattern:url` | any tool | Value matches URL glob |
| `cidr:n/m` | any tool | Value in IP range |

`{sandbox}` expands to the directory in `sandbox:`. You can point `subpath:` at any path. Tools unlisted aren't individually governed; they're caught by `default`.

For internal egress, `WebFetch` also accepts `cidrs:` (e.g., `cidrs: ["10.0.0.0/8"]`) to allow by IP range. It's off by default; add deliberately.

**Command tools.** `Bash`, `PowerShell`, and `Monitor` execute commands independently; govern each in `enforce:`. Use `shlex` for POSIX (Bash/Monitor) and `pattern`/`regex` for PowerShell (different dialect).

**MCP arguments.** Under `mcp.enforce:`, a bare constraint targets `path`. Use `arg: NAME` for other arguments, and `args: {NAME: constraint, …}` for multiple constraints.

**Three lists, plus two switches.**
- **`enforce:`** constrained (blocked if constraint fails)
- **`allow:`** unconstrained (always allowed, logged)
- **`default:`** catch-all for unlisted tools
  - **`default: deny`** recommended (fail-closed)
  - **`default: approve`** routes to human approval (Cloud only)
- **`mode:`** global posture
  - **`mode: enforce`** blocks denied calls
  - **`mode: dry-run`** logs decisions, blocks nothing (use to shadow a policy before enforcing)
- **`subagents:`** declares roles; each runs with attenuated authority
- **`ttl_seconds:`** warrant lifetime in seconds (default 3600 = 1h); `up` re-mints

After any edit, run `tenuo-claude refresh`.

**Ready-made policies:** [examples/policies/](examples/policies/).

## Commands

Day to day: `up` (start), `audit` (review), `refresh` (after editing policy).

| Command | What it does |
|---------|--------------|
| `onboard` | Interactive first-run wizard (`--local` / `--cloud`); same as `bootstrap` but with prompts. |
| `bootstrap` | Non-interactive setup: scaffold policy if none → `init` → `up` → `verify`. `--cloud` for Cloud mode; `--pack PACK` to use a policy pack. |
| `init` | Compile existing `tenuo.yaml`: mint warrant, wire hook and MCP proxy. |
| `up` / `down` | Start / stop the authorizer (auto-selects Docker or native; `--native` forces native). |
| `refresh` | Recompile after editing `tenuo.yaml` (restarts authorizer if running). |
| `verify [--deep]` | Self-test the policy against the authorizer (no Claude session needed). `--deep` adds SSRF/encoded-IP matrix and Bash deny cases. |
| `audit [--tail N] [--verify]` | Show the decision log (`.state/receipts.jsonl`). `--verify` checks receipt signatures, hash-chain links, and embedded evidence. |
| `check` | Preflight: dependencies, wiring, audit-sink health, leaked keys, Cloud bindings. |
| `status` | Warrant, mode, audit-sink health, Cloud summary. |
| `install-authorizer` | Install the pinned native authorizer to `~/.tenuo/bin`. |
| `bench [--json]` | Measure per-call overhead on your machine. |
| `revoke` | Revoke the current session warrant. |

The warrant is short-lived (~1h TTL); `up` refreshes it before expiry. Generated files (don't commit): `.state/` (keys, warrant, credentials), `.claude/settings.json` (hooks), `.mcp.json` (MCP proxy).

## Cloud Mode

For organizations: org root, fleet revocation, human approval, central audit.

### Setup (first time)

1. **Create a Tenuo tenant** at [cloud.tenuo.ai](https://cloud.tenuo.ai). Complete the **Infrastructure** onboarding (provisions KMS-backed signing keys).

2. **Get credentials:**
   - **Runtime key** (`tenuo_ct_…`) from Agents → Quick Connect → **Authorizer Only** → `.state/cloud.env`
   - **Tenant-admin key** (`tc_…`) from Settings → API Keys → Create (admin role) → `~/.tenuo/admin.env`

3. **Bootstrap with Cloud:**
   ```bash
   tenuo-claude bootstrap --native --pack filesystem-dev --cloud
   ```
   Behind the scenes: `tenuo-admin setup` registers this project, creates a Cloud trigger from `tenuo.yaml`, and mints a root-signed warrant.

4. **(Optional) Add human approval:**
   - Create an approver identity in Cloud (Dashboard → Channels → Identity Bindings)
   - Give it a notification channel (Slack, Telegram, console, etc.)
   - Gate any tool with `approval:` in `tenuo.yaml`

### Day to day (Cloud)

```bash
tenuo-claude check && tenuo-claude up
```

If `check` reports a **Cloud bindings** failure, run `tenuo-admin setup` and retry.

After editing `tenuo.yaml`:
```bash
tenuo-claude refresh
```

The Cloud-issued warrant stays active until revoked (or TTL expires). To revoke fleet-wide:
```bash
tenuo-claude revoke
```

~30 seconds later, all active sessions enforcing that warrant exit and must re-authorize.

**Important:** Once Cloud is configured, don't re-run plain `bootstrap` (it reverts to local mode). Use `check && up` on future sessions.

### Human Approval (Cloud)

Add `approval:` to any enforced tool:

```yaml
enforce:
  WebFetch:
    domains: ["api.github.com"]
    approval: true              # all URLs gated
    
  delete_deployment:            # MCP tool
    arg: target
    constraint: "oneof:staging,prod"
    approval:
      exempt: ["staging"]       # staging bypasses approval
```

When Claude tries a gated action:
1. The hook opens a Cloud approval request
2. The approver gets a Slack/Telegram/console notification
3. They review and approve/deny
4. The decision is recorded in the signed receipt (audit trail shows **who** approved)

**Setup:** See [docs/DETAILS.md § Approval setup runbook](docs/DETAILS.md#approval-setup-runbook).

For Cloud, receipts are sent to your tenant (central audit). Locally, receipts are always written to `.state/receipts.jsonl`.

## Security Model

Tenuo runs alongside Claude Code permissions; it doesn't replace them. The difference:

- **Claude Code permissions:** Prompt the user; can be bypassed with `--dangerously-skip-permissions`
- **Tenuo warrant:** Signed, expiring authority enforced by an authorizer before each call; cannot be disabled by the user or model

The warrant is a capability token: it lists what Claude can do and for how long. Each action is checked against the warrant before it runs. The same boundary applies regardless of why the model tried the call: prompt injection, hallucination, poisoned tool output, or direct user request.

**Receipts:** Every decision is signed with Ed25519 and hash-chained for tamper-evidence. Local `audit --verify` checks signatures, hash-chain links, warrant chains, and deterministic constraint replay. Cloud receipts are independently verified by the tenant.

**Fail-closed:** Missing or broken `tenuo.yaml` denies every governed call. Keys under `.state/` are owner-only. A broken receipt sink surfaces loudly (not silent data loss).

**Rolling out to a team:** Keep `tenuo.yaml` in version control. Push hook/MCP wiring through Claude Code managed settings. Use Cloud for org-root warrants, central audit, and revocation. See [docs/DETAILS.md § Managed deployment](docs/DETAILS.md#managed-deployment) for the rollout checklist and hardened socket setup.

**Turning it off:** `tenuo-claude disable` unwires the hook (Claude stops calling the authorizer) and stops the authorizer, leaving policy and warrant in place. `tenuo-claude uninstall` also deletes `.state/` (warrant, keys, credentials). `tenuo.yaml` is never touched.

---

## Build from Source

For development or running from a git checkout:

```bash
git clone https://github.com/tenuo-ai/tenuo-claude-code.git
cd tenuo-claude-code
uv venv && uv sync && source .venv/bin/activate    # Windows: .venv\Scripts\activate
chmod +x bin/tenuo-claude
uv run tenuo-claude install-authorizer             # only if not using Docker
```

Run via `./bin/tenuo-claude --help`, `uv run tenuo-claude --help`, or `pip install -e .`. Re-run `tenuo-claude init` (or `refresh`) after moving the repo or reinstalling.

Contributors: [CONTRIBUTING.md](CONTRIBUTING.md).

## Performance

Authorization is ~1–3 ms per call; the PreToolUse hook adds ~100–200 ms (mostly process startup). Measure on your machine:

```bash
tenuo-claude bench
```

## About

**Repository:** [tenuo-ai/tenuo-claude-code](https://github.com/tenuo-ai/tenuo-claude-code)  
**PyPI:** [tenuo-claude-code](https://pypi.org/project/tenuo-claude-code/)  
**Tenuo core:** [tenuo-ai/tenuo](https://github.com/tenuo-ai/tenuo)  
**License:** [Apache 2.0](LICENSE)

| | Path |
|---|---|
| **Package source** | `src/tenuo_claude_code/` |
| **Policy packs** | `examples/policies/` |
| **Reference demo** | `demo/` |
| **Implementation details** | `docs/DETAILS.md` |
| **Troubleshooting** | `docs/TROUBLESHOOTING.md` |
| **Security** | `SECURITY.md` |
