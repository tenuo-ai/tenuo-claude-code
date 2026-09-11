# Implementation details

How `tenuo-claude-code` works under the hood, for when the [README](../README.md) isn't enough. Install and commands are in the README; common errors in [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

The honest framing for the whole system: Tenuo checks the **arguments of each tool call** against a signed policy at the tool-call boundary. It validates the *string* the model passes (a path, a command, a URL). It is not a kernel sandbox and does not follow what a URL resolves to at connect time. Trust boundaries: [The Map is not the Territory](https://niyikiza.com/posts/map-territory/).

**Contents:** [Enforcement model](#why-hook-and-mcp-proxy) · [What's in scope](#agent-tools-vs-operator-shell) · [Fail-closed & exit codes](#hook-exit-codes-and-fail-closed) · [Constraints: Bash](#bash-shlex-not-regex) · [Constraints: WebFetch](#webfetch-egress) · [Path constraints & symlinks](#search-tools-and-symlinks) · [Subagents](#subagents) · [Dry-run mode](#dry-run-mode-mode-dry-run) · [Refresh & TTL](#policy-refresh-tenuo-claude-refresh) · [Receipts](#receipts) · [Cloud: check](#preflight-and-cloud-bindings-tenuo-claude-check) · [Cloud: approval](#human-approval-cloud) · [Cloud: extended](#tenuo-cloud-extended)

---

## Why hook and MCP proxy

Enforcement has two interception points, both checking the **same warrant against the same authorizer**:

| Path | How it's intercepted |
|------|----------------------|
| Native tools (Read, Bash, WebFetch, …) | Claude Code **PreToolUse hook**: Claude must honor the allow/deny it returns |
| MCP tools | An **MCP proxy** that Claude is wired to *instead of* the downstream server |

Two points exist because the failure modes differ. The native hook is the only interception option for built-in tools, so it's mandatory there. For MCP you *could* point `.mcp.json` at the downstream server and rely on the hook alone, but the proxy means that if the hook is ever removed or fails, denied MCP calls still never reach the server. (The hook also checks `mcp__…` tool names against the same `mcp.enforce` policy, so the two agree.)

## Agent tools vs operator shell

Tenuo governs **model-invoked tool calls** only:

| Path | Who triggers it | Governed? |
|------|-----------------|-----------|
| Bash, Read, WebFetch, MCP, subagent spawns | The model, as a tool call | **Yes** |
| The TUI `!` input-box shell | The operator, by typing | No, not a tool call |

The model cannot invoke `!`. Whatever the cause (prompt injection, hallucination, context drift, a malicious user, a poisoned tool input), any out-of-scope action the *agent* takes flows through a tool call and stays on the governed path, denied identically regardless of cause. `!` is a separate operator affordance the hook never sees.

## Hook exit codes and fail-closed

Claude Code blocks a PreToolUse call only on **exit code 2** or an explicit `deny`. Exit code 1 (including an unhandled traceback) is **non-blocking**, and the call would proceed. So the hook wraps its body in a fail-closed guard: any internal error becomes an explicit deny, never a bare exception. A missing or broken `tenuo.yaml` therefore denies every governed call until it's fixed.

`verify --deep` runs a live canary when `claude` is on PATH (`--no-live` to skip): the test hook writes a marker file before exiting, so verify can tell "hook never ran" apart from "exit 2 didn't block."

## Bash: `shlex` not `regex`

`shlex:` is structure-aware. It rejects pipes, chaining (`&&`/`;`), subshells, and variable/glob expansion that a `regex:.*` would wave through (e.g. `ls && rm -rf /`). But it authorizes the **verb**, not file paths: with `shlex:cat`, `cat /etc/passwd` still passes. Scope the filesystem with `Read`/`Write`/`Edit` (`subpath`), and for a hard lock, drop `Bash` from `enforce` entirely.

## WebFetch egress

A WebFetch policy compiles to two checks:

1. **`UrlSafe` SSRF hygiene** on the raw URL string: https-only by default, with loopback, cloud-metadata IPs (`169.254.169.254`), and decimal/hex/octal-encoded IPs blocked.
2. **Host match** against the `domains` allowlist (`*` matches one label) and/or `cidrs`.

Cases `verify` exercises:

| URL | Result |
|-----|--------|
| `https://api.github.com`, `https://raw.githubusercontent.com/…` | allow |
| `https://evil.com` | deny (off-allowlist) |
| `http://api.github.com` | deny (plain http) |
| `http://169.254.169.254/latest/meta-data/` | deny (metadata) |
| `http://2130706433/`, `http://0x7f000001/` | deny (encoded loopback) |
| `https://api.github.com.evil.com/` | deny (suffix spoof) |
| `https://api.github.com@evil.com/` | deny (userinfo spoof) |

This is Map-level validation: it checks the string Claude passes, not what DNS resolves to at connect time. DNS rebinding and redirects need complementary controls in the fetching process. With an approval gate, an off-allowlist (but SSRF-safe) URL can pause for sign-off instead of being denied; SSRF-hygiene failures are always hard-denied and never reach the gate. Cloud triggers enforce the same `url_safe` field set as local minting (domain allowlist, schemes, ports, internal-CIDR egress).

`approval` cannot be combined with `cidrs`: the gate wildcards the host and turns off `block_private`, so a `cidrs:` allowlist would silently widen to every private range (and the gate's exempt is domain-based, not CIDR-aware). Use `domains:` with `approval`, or drop `approval` to hard-enforce the `cidrs` allowlist. The combination is rejected at config load.

## Search tools and symlinks

`Glob`/`Grep` search roots are constrained exactly like `Read`. A bare `Grep` with no path is checked against the hook's cwd and denied if that's outside the directory. All `subpath` arguments are `realpath()`-resolved before the check, so `ln -s /etc/passwd sandbox/escape.txt` can't smuggle a read out (`verify` plants this case). Races between check and open still need execution-time guards like `path_jail`.

## Subagents

When `subagents:` is declared, you get two layers:

1. **Spawn gate**: `spawn_agent` is a signed capability whose `subagent_type` is constrained to a `oneof` of your declared roles. Undeclared spawns are denied by the warrant, not by a string check in the hook.
2. **Per-role warrant**: each role runs under the session warrant **attenuated** to its `tools`. The session is the ceiling; attenuation is one-way and cryptographic, so a subagent can only ever do *less*.

Roles must match a real `subagent_type` (`.claude/agents/<name>.md` frontmatter `name:`, or a built-in); `verify` and `status` check this. Omit `subagents:` for flat coverage: spawns are then audited, not gated, and the subagent runs under the full session warrant.

Changing `subagents:` is a policy change: re-run `tenuo-admin setup` (Cloud) or `init` (local). Note one sharp edge: the bundled `Workflow` harness tool tags its inner calls with an `agent_type` that isn't a declared role, so under `subagents:` those inner calls are denied. Remove `Workflow` from the `allow:` list or omit `subagents:` if you need it. Requires `tenuo` ≥ 0.3.0 and authorizer `0.3.0` (pinned in `cli.py`).

## Dry-run mode (`mode: dry-run`)

(`mode: audit` is a deprecated alias for `dry-run`.) Shadow mode: every call's real allow/deny is still computed against the warrant and written to the receipt log, but **nothing is blocked**. The hook deliberately emits *no* permission decision in this mode (not even "allow") because an explicit hook-allow would auto-approve calls that Claude's own settings might otherwise prompt on. So observe-only stays observe-only, and Claude's prompts remain in effect.

Roll out by watching `WOULD-DENY` rows in `tenuo-claude audit`, tuning policy, then switching to `mode: enforce`. The hook reads `mode` live (next tool call); the MCP proxy picks it up on the next Claude session.

`mode:` is a **global** switch and `default:` is the **catch-all for unlisted tools** only; they are independent. In `mode: dry-run` nothing is enforced (even tools listed under `enforce:`), so `default:` has no effect until you switch back to `mode: enforce`. Do not confuse the two: there is no `default: dry-run`. There is also no permissive catch-all: `default:` is either `deny` (block unlisted, fail-closed) or `approve` (route unlisted to a Cloud human-approval gate). To permit specific tools unconstrained, list them under `allow:`.

`mode: audit` is a deprecated alias for `mode: dry-run`; it still works and `tenuo-claude check` / `status` flag it so you can migrate. `default: allow` / `default: audit` are no longer supported (enforce must not fail open): they collapse to `default: deny` and are surfaced as a posture warning. Any other *unrecognized* `mode:` or `default:` value (a typo, or putting `allow` on `mode:` when you meant `default:`) likewise falls back to the safe default (`enforce` / `deny`) rather than silently changing behavior.

## Policy refresh (`tenuo-claude refresh`)

After editing warrant-backed policy (`enforce`, `default`, `audit_*`, `subagents`, `mcp`, approval overlay), run `refresh`. It re-mints the session warrant (or re-fires the Cloud trigger), regenerates the gateway config, rewires hooks, and restarts the authorizer if it's running.

- **`mode` change only** (`dry-run`/`audit` ↔ `enforce`): no refresh is needed for the native hook, which reads the file live. `refresh` is still safe and is the simplest habit, especially if you also govern MCP tools (the proxy sees the new posture on the next Claude session).
- **Cloud capability change**: the warrant's capabilities come from the trigger config on the control plane, so re-run `tenuo-admin setup` first, then `refresh`.

### Warrant TTL and refresh

Session warrants have a ~1h TTL; `status` flags `EXPIRED` when one lapses. `tenuo-claude up` refreshes even while the authorizer runs (Cloud re-fires the trigger, local re-mints with the same issuer key) with no container restart (the warrant rides in each request header). Subagent child warrants are re-derived from the fresh session warrant.

## Receipts

`PreToolUse`/`PostToolUse` use match-all hooks; MCP tools are also gated by the proxy. Every governed call is **proof-of-possession-signed and checked by the authorizer**:

- **Enforced** tools: argument-checked; out-of-scope denied.
- **Allowed** tools (the `allow:` permit-list and bundled harness tools): permitted unconstrained, logged, not blocked.
- **Default**: everything else denied (`default: deny`), or routed to a Cloud human-approval gate (`default: approve`).

The hook appends a signed local JSON line per call to `.state/receipts.jsonl`.
`tenuo-claude audit` pretty-prints it; `tenuo-claude audit --verify` checks the
receipt signature, hash-chain link, warrant chain, and recorded authorization
evidence. For Cloud-approved calls, the local receipt stores the approval CBOR
presented to the authorizer; independent approver identity and threshold replay
requires Cloud audit because it depends on the linked Cloud approval policy:

```json
{"phase": "pre", "decision": "deny", "claude_tool": "Bash", "governed": true,
 "args": {"command": "ls && rm -rf /"}, "reason": "Constraint not satisfied"}
```

In dry-run mode, denials are recorded as `WOULD-DENY`. Subagent calls carry `agent_type` so the hook enforces the right child warrant (this depends on Claude Code populating `agent_type`). When connected to Cloud, the authorizer also streams receipts to your tenant audit plane. Measure overhead with `tenuo-claude bench`.

## Production wiring

Hooks are wired to a PATH-independent launcher. In PyPI installs this is usually
`<python> -m tenuo_claude_code.cli`; in a checkout it may be the absolute
`bin/tenuo-claude` path. On POSIX, the PreToolUse hook is wrapped in a small
`/bin/sh` guard so a moved or deleted launcher emits an explicit deny instead of
silently allowing the tool call.

The MCP proxy uses the same launcher resolution, without the PreToolUse deny
guard. Project files (`tenuo.yaml`, `.state/`) live in your governed project
directory, not the package install path. Discovery: `tenuo.yaml` in the cwd or
any parent, or set `TENUO_PROJECT_DIR`.

## Preflight and Cloud bindings (`tenuo-claude check`)

`check` validates Python deps, the authorizer runtime, and hook/MCP wiring, and when Cloud artifacts exist and a tenant-admin key is in `~/.tenuo/admin.env`, the live control-plane **bindings**:

- local holder public key (`.state/holder_key.b64`) vs the Cloud agent's claimed key,
- the agent's `allowed_triggers` vs the configured trigger id,
- a runtime-key **dry-run trigger fire** (`would_issue=true`).

Any failure suggests `tenuo-admin setup`. Day-to-day Cloud flow is `tenuo-claude check && tenuo-claude up`; common binding failures are in [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Human approval (Cloud)

When a warrant includes **approval gates**, a governed call can return `approval-required` (authorizer code `1707`) instead of allow/deny. The hook handles this for any tool on the path:

1. First authorization → `approval-required` with a request hash.
2. Hook opens a Cloud approval request (holder-signed context attestation).
3. Approver responds on their configured notification channel.
4. Hook re-authorizes with `X-Tenuo-Approvals` carrying the Cloud KMS signatures.

This is **Cloud-only**: gates carry the approver's KMS public keys from the linked approval policy; there's no local fallback, so without Cloud a gated call that needs sign-off is denied.

### Approval setup runbook

Setting up approvals spans two places: you create the **approver** in the Tenuo Cloud console, then wire the **gate** with this CLI. The CLI only references an approver identity that already exists in Cloud; it does not create the identity or its notification channel.

1. **Start from a Cloud-ready tenant.** Make sure Infrastructure onboarding has provisioned an active root key, and have both credentials ready: the Authorizer Only Quick Connect token and a tenant-admin API key. Approval has no local fallback; without Cloud a gated call is denied.
2. **Create the approver in [Tenuo Cloud](https://cloud.tenuo.ai).** Use Dashboard → Channels → Identity Bindings (or the equivalent approval identity flow) to make an identity with a KMS signing key and a notification channel (Slack, Telegram, or console), then copy its identity id. *(This step lives in the Cloud console.)*
3. **Gate something and point it at that approver.** For a fresh project, run `tenuo-claude bootstrap --cloud --advanced --approver-id <id>`. On an existing Cloud project, run `tenuo-claude init --advanced --approver-id <id>` (or `--approver "<display name>"` for demos), then add/adjust an `approval:` block on a tool or set `default: approve`. The generated WebFetch example includes `domains: ["docs.anthropic.com"]`; allowlisted domains auto-allow, other SSRF-safe hosts pause for sign-off, and metadata/SSRF URLs are still hard-denied.
4. **Publish the gate:** run `tenuo-admin setup`. Setup creates or updates the holder agent and Cloud trigger from `tenuo.yaml`, reconciles the agent's `allowed_triggers`, creates or reuses a Cloud approval policy for the approver, bakes `approval_gates` into the trigger warrant config (with `_policy_id` for offline verification), syncs the local gateway, and reloads a running authorizer so new MCP routes work immediately.
5. **Test end to end:** `tenuo-claude demo --advanced --live-approval`.

Receipts show `PENDING [appr]` while parked, then `ALLOW`/`DENY`. In dry-run mode the gate is reported only, never blocks. **Live approval blocks the tool call** until the approver responds or it times out, so make sure the identity is reachable first, or Claude's hook timeout can expire and look like a deny.

Cloud's Claude Code starter is a warrant template, not a complete trigger. `tenuo-admin setup` supplies the missing project-specific pieces: holder, sandbox paths, concrete native and MCP capabilities, trigger binding, and approval policy id.

Two shipped examples:

| Example | Path | Gated → pauses | Exempt / hard-denied |
|---------|------|----------------|----------------------|
| Off-allowlist `WebFetch` | native hook | SSRF-safe URL off the domain allowlist | allowlisted domain → allowed; SSRF/metadata → hard-denied |
| `delete_deployment` | MCP proxy | `target=production` | `target=staging` → allowed; unlisted tool → denied |

```yaml
enforce:
  WebFetch:
    domains: ["docs.anthropic.com"]
    approval:
      threshold: 1

mcp:
  enforce:
    delete_deployment:
      approval:
        threshold: 1
        exempt:
          target: "exact:staging"
```

Try it in the [reference demo](../demo/): `tenuo-claude demo --advanced --live-approval` once approval is configured.

## Tenuo Cloud (extended)

By default `init` mints warrants from a **local issuer key**. With [Cloud](https://cloud.tenuo.ai), warrants are issued by your **tenant root** via a trigger, the pattern most orgs use in production: one audit stream, central revocation, admin/runtime key separation, and optional org-wide hook deployment through Claude Code managed settings (policy enforced outside Claude's permission UI).

The admin registers the holder and creates or updates the trigger; runtime only *fires* it. During setup, the trigger is built from `tenuo.yaml` plus any overlays (`tenuo.cloud.yaml`, `tenuo.advanced.yaml`), then bound to the local holder agent. Cloud's Claude Code starter warrant template documents the recommended shape, but the trigger is project-specific. Runtime refuses to start if an admin key is reachable, and the first trigger fire locks to the discovered runtime service account.

**Revocation:** Cloud revokes by warrant id and the authorizer pulls the signed revocation list within ~30s. Locally, `tenuo-claude revoke` writes a signed SRL and reloads.

Non-interactive Cloud setup (CI), in one shot:

```bash
TENUO_CONNECT_TOKEN="tenuo_ct_…" TENUO_ADMIN_KEY="tc_…" tenuo-claude bootstrap --cloud --yes
```

For a native-authorizer path without Docker:

```bash
tenuo-claude install-authorizer
TENUO_AUTHORIZER_BACKEND=native TENUO_CONNECT_TOKEN="tenuo_ct_…" \
  TENUO_ADMIN_KEY="tc_…" tenuo-claude bootstrap --cloud --yes
```

Pass credentials as flags or one-shot env, not a persistent `export TENUO_ADMIN_KEY`, and unset the admin key before `tenuo-claude up`. Manual step-by-step (equivalent to the wizard): `init --cloud` (writes a `cloud.env.example` to fill in) → put the tenant-admin key in `~/.tenuo/admin.env` → `tenuo-admin setup` → `check && up` → `verify`.
