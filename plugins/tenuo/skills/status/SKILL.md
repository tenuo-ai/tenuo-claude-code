---
name: status
description: Show Tenuo governance status for this project (policy, warrant, authorizer, hook wiring) by running `tenuo-claude check`.
disable-model-invocation: true
allowed-tools: Bash(python3 *)
---

Tenuo plugin status and `tenuo-claude check` output, run from the governed project (the directory holding `tenuo.yaml`):

```
!`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/tenuo_plugin.py" run check 2>&1`
```

Show the user that output verbatim, then add at most three short lines:

- If it says `tenuo-claude not found`, tell the user to install it with `uv tool install tenuo-claude-code` (or `pipx install tenuo-claude-code`).
- If it says there is no `tenuo.yaml`, say Tenuo is not active here and the next step is `tenuo-claude bootstrap --native --pack filesystem-dev`.
- If the `Plugin:` line says the project is governed via the Tenuo plugin, a `claude hooks: not wired yet` line from `check` is expected: the plugin's hooks are doing the enforcement. Do not call that a problem.
- Otherwise, if any check failed, name the failing line and the fix it suggests.

Do not suggest widening the Tenuo policy (for example adding commands to the Bash allowlist).
