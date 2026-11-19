# Tenuo plugin for Claude Code

Give Claude Code real access and keep it in bounds. Tenuo limits each tool and MCP server to the repos, folders, shell commands and web domains you name, and keeps a signed record of every allowed and denied call.

## Install

```bash
claude plugin install tenuo --marketplace tenuo-ai/tenuo-claude-code
```

Then open Claude Code in your project and run `/tenuo:setup`, or ask for it in your own words ("limit Claude to this repo and keep a log of what it does"). Setup starts in observe-only mode: calls are logged, nothing is blocked, until you switch the policy to `mode: enforce`.

## Skills

| Skill | What it does |
|---|---|
| `/tenuo:setup` | Installs the `tenuo-claude` CLI, writes a starter policy, verifies the authorizer; checks and repairs an existing setup. Asks before installing anything. |
| `/tenuo:status` | Shows whether this project is governed and whether it is observing or enforcing. Read-only. |
| `/tenuo:audit` | Shows and verifies the signed record of allowed and denied calls. Read-only. |

Claude can run all three when you ask in plain language.

## Hooks

PreToolUse, PostToolUse and SessionStart hooks run in every project, and do nothing unless the project has a `tenuo.yaml` and has been initialized. In a governed project whose settings wiring is missing, the plugin routes each call to `tenuo-claude` itself and denies the call if the CLI cannot be found.

Installing the plugin does not turn governance on, and removing it does not remove CLI-managed project wiring (`tenuo-claude disable` or `uninstall` does).

macOS and Linux. Full documentation: [tenuo-ai/tenuo-claude-code](https://github.com/tenuo-ai/tenuo-claude-code#readme).
