---
name: audit
description: Verify Tenuo's signed allow/deny receipts for this project (signatures, hash chain, warrant replay) by running `tenuo-claude audit --verify`.
disable-model-invocation: true
allowed-tools: Bash(python3 *)
---

Output of `tenuo-claude audit --verify`, run from the governed project:

```
!`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/tenuo_plugin.py" run audit --verify 2>&1`
```

Show the user that output verbatim (if it is very long, show the summary and the deny lines), then summarize in at most three short lines: how many receipts verified, how many denies, and any verification failure. A broken signature or hash chain means the receipt log was modified and should be treated as a security issue.

If it says `tenuo-claude not found`, tell the user to install it with `uv tool install tenuo-claude-code`. If it says there is no `tenuo.yaml`, say Tenuo is not active here.
