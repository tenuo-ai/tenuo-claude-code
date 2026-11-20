---
name: status
description: Show whether Tenuo is governing this project and what it is doing (observing or enforcing, policy, warrant, authorizer). Use when the user asks if Tenuo is on, whether Claude's tool calls are being limited or logged here, or why Tenuo looks broken. Read-only.
---

Run `tenuo-claude status` in the project directory, as one plain command. If the command is not found, run `uv tool dir --bin` and use the `tenuo-claude` in that directory by its full path.

Start with one line that answers the question in plain words, then show the output, then add at most three short lines.

- **Not set up**: the command says there is no `tenuo.yaml`, or the CLI is not installed. Claude Code's own permissions apply; `/tenuo:setup` turns Tenuo on, starting in observe-only mode.
- **Observing**: the output has `DRY-RUN — observe-only`. Calls are logged and nothing is blocked.
- **Enforcing**: no `DRY-RUN` line and the authorizer is up. Out-of-policy calls are blocked. If the output shows enforcement pinned by an organization, say that.
- **Enforcing, and this command was denied**: if Tenuo itself refuses the `status` command, that is the policy at work, because the starter policy allows only `ls` and `pwd` in the shell. Say Tenuo is enforcing here and give the user `tenuo-claude status` to run in their own terminal. Do not retry or look for another way to run it.
- **Authorizer down**: run `tenuo-claude check` as well. If it says the Claude hooks are not wired, Tenuo is **disabled** here and nothing is logged or blocked; `tenuo-claude up` turns it back on. If the hooks are wired, every governed call is being denied until the user runs `tenuo-claude up`.
- **Warrant expired** and the output does not say it renews: the fix is `tenuo-claude up`.

This is read-only. Do not start services, refresh warrants or change the policy, and do not suggest widening the policy, for example by adding commands to the shell allowlist. The output describes on-disk state and the authorizer, not whether this running session loaded the hooks.
