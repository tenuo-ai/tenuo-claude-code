---
name: status
description: Show whether Tenuo is governing this project and what it is doing (observing or enforcing, policy, warrant, authorizer, hook wiring). Use when the user asks if Tenuo is on, whether Claude's tool calls are being limited or logged here, or why Tenuo looks broken. Read-only.
allowed-tools: Bash(python3 "${CLAUDE_PLUGIN_ROOT}/scripts/tenuo_plugin.py" run *)
---

Tenuo plugin status and `tenuo-claude status` output, run from the governed project (the directory holding `tenuo.yaml`):

```
!`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/tenuo_plugin.py" run status`
```

Start with one line that answers the question in plain words: **Not set up**, **Disabled**, **Observing** (calls are logged, nothing is blocked), **Enforcing** (out-of-policy calls are blocked), or **Denying every call until fixed**. Take it from the `Plugin:` line first: when that line says governance is disabled for the project, the answer is **Disabled** (nothing is logged or blocked here, whatever mode the policy file names; `tenuo-claude up` turns it back on). If the output shows enforcement pinned by an organization, say that separately. Then show the user that output verbatim, then add at most three short lines:

- If it says there is no `tenuo.yaml` in this directory or any parent, Tenuo is not set up here: say Claude Code's own permissions apply and that `/tenuo:setup` turns it on (it starts in observe-only mode).
- If it says `tenuo-claude not found`, or that the only copy is inside the project, the status could not be read. That does not mean governance is off: report what the `Plugin:` line says (a governed project without the CLI denies tool calls until the CLI is installed) and give the install command.
- If the `Plugin:` line says tool calls will be denied until something is fixed (for example `TENUO_PROJECT_DIR` pointing at a directory without a policy), say calls are being denied and give the fix it names. Do not describe that as Tenuo being inactive.
- If the output ends with `[tenuo-claude exited N]`, the command failed: name the failing line and the fix it suggests.
- If something looks wrong and the output does not say why, the full preflight is `tenuo-claude check`, which the user runs in a terminal (use the path on the `CLI:` line).
- If the warrant is expired and the output does not say it renews, the fix is `tenuo-claude up`, using the full path on the `CLI:` line when `tenuo-claude` is not on `PATH`.

Do not suggest widening the Tenuo policy (for example adding commands to the Bash allowlist).

This is read-only: do not start services, refresh warrants, or change policy. Dry-run means observation, not blocking. The output describes on-disk state and authorizer health, not whether this running session loaded the hooks.
