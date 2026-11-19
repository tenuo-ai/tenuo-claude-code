---
name: status
description: Show whether Tenuo is governing this project and what it is doing (observing or enforcing, policy, warrant, authorizer, hook wiring). Use when the user asks if Tenuo is on, whether Claude's tool calls are being limited or logged here, or why Tenuo looks broken. Read-only.
allowed-tools: Bash(python3 "${CLAUDE_PLUGIN_ROOT}/scripts/tenuo_plugin.py" run *)
---

Tenuo plugin status and `tenuo-claude check` output, run from the governed project (the directory holding `tenuo.yaml`):

```
!`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/tenuo_plugin.py" run check`
```

Show the user that output verbatim, then add at most three short lines:

- If it says there is no `tenuo.yaml` in this directory or any parent, Tenuo is not set up here: say Claude Code's own permissions apply and that `/tenuo:setup` turns it on (it starts in observe-only mode).
- If it says `tenuo-claude not found`, the check could not run. That does not mean governance is off: report what the `Plugin:` line says (a governed project without the CLI denies tool calls until the CLI is installed) and give the install command.
- If the `Plugin:` line says tool calls will be denied until something is fixed (for example `TENUO_PROJECT_DIR` pointing at a directory without a policy), say calls are being denied and give the fix it names. Do not describe that as Tenuo being inactive.
- If the `Plugin:` line says the project is governed via the Tenuo plugin, a `claude hooks: not wired yet` line from `check` is expected: the plugin's hooks are doing the enforcement. Do not call that a problem.
- If the output ends with `[tenuo-claude exited N]`, a check failed: name the failing line and the fix it suggests.

Do not suggest widening the Tenuo policy (for example adding commands to the Bash allowlist).

This is read-only: do not start services, refresh warrants, or change policy. Dry-run means observation, not blocking. Passing checks describe on-disk wiring and authorizer health, not whether this running session loaded the hooks.
