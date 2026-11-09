# Troubleshooting (Q&A)

Common setup and runtime issues for **tenuo-claude-code**. For install paths see
[README.md](../README.md). For behavior details see [DETAILS.md](DETAILS.md).

Run **`tenuo-claude check`** first. It validates credentials, wiring drift, and
(when Cloud is configured) live agent/trigger/holder bindings before you start the
authorizer.

---

## Getting started

### Which command should I run first?

**Local evaluation (no Cloud):**

```bash
tenuo-claude install-authorizer
export TENUO_AUTHORIZER_BACKEND=native
tenuo-claude bootstrap
```

**Cloud (new project):**

```bash
tenuo-claude install-authorizer
export TENUO_AUTHORIZER_BACKEND=native
tenuo-claude bootstrap --cloud
# or: tenuo-claude onboard --cloud
```

**Cloud (returning / demo day):**

```bash
tenuo-claude check && tenuo-claude up
```

If `check` reports **cloud bindings** failure → `tenuo-admin setup`, then retry.

**Git checkout of this repo:** activate the project venv first (`uv sync &&
source .venv/bin/activate` from repo root), then run commands from your governed
project directory (e.g. `demo/`).

### What is the difference between `up`, `setup`, and `refresh`?

| Command | Who runs it | What it does |
|---------|-------------|--------------|
| `tenuo-claude up` | Developer | Starts authorizer; refreshes expired Cloud warrant (fires trigger) |
| `tenuo-admin setup` | Admin (once / after Cloud policy changes) | Registers holder agent, syncs trigger from `tenuo.yaml`, reconciles bindings, re-claims holder if drifted |
| `tenuo-claude refresh` | Developer | Re-applies local `tenuo.yaml` (wiring, gateway, warrant/subwarrants); restarts authorizer if up |

**Rule of thumb:** day-to-day = `check` + `up`. After changing `enforce`, `mcp`, or `subagents` on Cloud → `tenuo-admin setup`. After changing `mode` only → `refresh` (no setup needed).

### Can I run plain `bootstrap` on the reference demo?

**No**, if `<state>/cloud.env` or `tenuo.cloud.yaml` already exists. Plain
`bootstrap` switches to local mode and moves Cloud files aside (`.bak`).

Use `tenuo-claude check && tenuo-claude up`, or re-onboard with
`tenuo-claude onboard --cloud`.

---

## Cloud credentials

### Why two keys?

| Key | File | Used by |
|-----|------|---------|
| **Runtime** (Quick Connect, Authorizer Only) | `<state>/cloud.env` | `tenuo-claude up`, hooks, trigger fire |
| **Tenant admin** | `~/.tenuo/admin.env` | `tenuo-admin setup` only |

Runtime must **never** see the admin key; `tenuo-claude` refuses to start if
`TENUO_ADMIN_KEY` is exported in the shell.

### Quick Connect: Authorizer Only or Agent + Authorizer?

Use **Authorizer Only**. The hook signs proof-of-possession with a local holder key
(`<state>/holder_key.b64`) that `tenuo-admin setup` registers on Cloud. **Agent +
Authorizer** auto-claims a different key and breaks warrant alignment.

### I pasted an `ak_…` value and auth fails

`ak_…` entries in the dashboard are **key IDs**, not secrets. Use the Quick Connect
token (`tenuo_ct_…`) or the Manual tab `tc_…` bearer key in `<state>/cloud.env`.

### `Invalid TENUO_CONNECT_TOKEN: base64 decode error`

The Quick Connect token was copied incompletely or with extra characters. Use the
single `tenuo_ct_…` token value only; don't include `export`, surrounding prose,
spaces, or a trailing quote. If your terminal wrapped the line visually, copy it
again from Cloud as one continuous token.

---

## Cloud errors

### `Trigger fire failed (403): agent_not_allowed`

The holder agent on Cloud is not allowed to fire your configured trigger (stale
`allowed_triggers`, often after a rename or partial setup).

**Fix:**

```bash
tenuo-admin setup
tenuo-claude check && tenuo-claude up
```

`check` → **cloud bindings** should show `trigger fire dry-run OK` before you rely
on `up`.

### `Holder signing key mismatch` / `DelegationAuthorityError`

Local `<state>/holder_key.b64` drifted from the key claimed on Cloud (e.g. re-ran
`init` or plain `bootstrap` after Cloud was configured).

**Fix:**

```bash
tenuo-admin setup    # re-claims holder key when drift is detected
tenuo-claude up
```

### `check` says **cloud bindings** failed

All binding failures (`allowed_triggers missing`, `holder key mismatch`,
`agent not allowed to fire`) resolve with:

```bash
tenuo-admin setup
tenuo-claude check && tenuo-claude up
```

If `check` shows **`admin.env missing`**, add your tenant-admin key to
`~/.tenuo/admin.env`; `check` then compares the local holder key to Cloud and
dry-runs the trigger fire before `up`.

### `Refusing to run: TENUO_ADMIN_KEY is present in the runtime environment`

You exported the admin key in the same shell as `tenuo-claude up`.

**Fix:**

```bash
unset TENUO_ADMIN_KEY TENUO_ADMIN_API_KEY
tenuo-claude up
```

Keep admin credentials only in `~/.tenuo/admin.env` for `tenuo-admin`.

---

## Local runtime

### `Warrant expired — refreshing…` then an error

Normal prefix: `up` tries to refresh the session warrant. If refresh fails, see
Cloud errors above or run `tenuo-claude check`.

### Port 9090 already in use

Another authorizer or stale process holds the port.

**Fix:**

```bash
tenuo-claude down
# or: export TENUO_AUTHORIZER_PORT=9091
tenuo-claude up
```

### `verify` fails with `Signature verification failed`

Authorizer is up but the warrant/trust anchor does not match (stale container,
mixed local/Cloud mode, or warrant not refreshed).

**Fix:**

```bash
tenuo-claude down
tenuo-claude check
tenuo-admin setup    # Cloud only, if bindings were stale
tenuo-claude up
tenuo-claude verify
```

### Hooks call the wrong Python / `ModuleNotFoundError`

Hooks pin `sys.executable` at `init`/`refresh` time.

**Fix:** activate the same venv you use for demos, then:

```bash
tenuo-claude refresh
```

From a git checkout, always `source .venv/bin/activate` before `init`/`refresh`.

### `tenuo-claude demo` fails immediately

Authorizer is not running.

**Fix:**

```bash
tenuo-claude check && tenuo-claude up
tenuo-claude demo
```

### How do I turn governance off?

`tenuo-claude down` only stops the authorizer; the `PreToolUse` hook is still
wired, so the next tool call fails closed (authorizer unreachable). To actually
stop governance, remove the wiring:

```bash
tenuo-claude disable      # unwire hooks + stop authorizer; keeps policy/warrant
# re-enable later with:
tenuo-claude up
```

To remove everything (also deletes the state directory: warrant, keys, gateway, receipts,
Cloud credentials; `tenuo.yaml` is left untouched):

```bash
tenuo-claude uninstall            # prompts first
tenuo-claude uninstall --yes      # no prompt
tenuo-claude uninstall --keep-state   # unwire + stop, but keep the state directory
```

### My agent is blocked but I'm in Cursor, not Claude Code

Cursor can import and run a project's `.claude/settings.json` (including the
Tenuo `PreToolUse` hook) when **Settings → Rules, Skills, Subagents → "Include
third-party Plugins, Skills, and other configs"** is on. With that enabled, the
Cursor agent's tool calls go through the authorizer too. To stop it, either turn
that Cursor setting off, or run `tenuo-claude disable` to remove the wiring. The
**Hooks** output channel (bottom panel) shows which config the firing hook came
from.

### `mode:` / `default:` doesn't seem to take effect

Run `tenuo-claude check` (or `status`) and look at the `posture` line. An
*unrecognized* value is treated as the safe default (`enforce` / `deny`) and
flagged there rather than silently applied.

`mode:` and `default:` are different switches. `mode:` is global:
`mode: dry-run` logs but blocks nothing, even tools listed under `enforce:`
(the old `mode: audit` is an alias). `default:` is only the catch-all for
unlisted tools: `default: deny` blocks them (fail-closed), `default: approve`
routes them to a Cloud human-approval gate. `default: allow` / `default: audit`
are no longer supported (enforce must not fail open) and collapse to `deny`. In
`mode: dry-run`, `default:` has no effect because nothing is enforced. To stop
blocking everything while still logging, set `mode: dry-run` (there is no
permissive default); to permit specific tools unconstrained, list them under
`allow:`.

---

## Policy changes

### I edited `tenuo.yaml`: what do I run?

| Change | Command |
|--------|---------|
| `mode: dry-run` ↔ `mode: enforce` only | No command is strictly required for the native hook; `tenuo-claude refresh` is safe and keeps wiring/gateway state tidy |
| `enforce`, `mcp`, `subagents`, approval overlay (Cloud) | `tenuo-admin setup` then `tenuo-claude refresh` or `up` |
| Local-only project (no Cloud) | `tenuo-claude refresh` |

---

## Still stuck?

1. `tenuo-claude check`
2. `tenuo-claude status`
3. `tenuo-admin show`
4. Re-run `tenuo-admin setup` if Cloud is involved
5. Share the `trace_id` from Cloud API errors with support if it keeps failing
