# Tenuo plugin for Claude Code

Give Claude Code real access and keep it in bounds. Tenuo limits each tool and MCP server to the repos, folders, shell commands and web domains you name, and keeps a signed record of every allowed and denied call.

Works in Claude Code on macOS and Linux. The plugin's hooks do not run in claude.ai chat, so it does nothing there.

## Nothing happens until you opt in

Installing the plugin does not limit, block or log anything. Tenuo acts only in a project where you ran setup, and setup starts in observe-only mode: calls are recorded, none are blocked. Blocking starts when you change the policy to `mode: enforce` yourself. `tenuo-claude disable` turns it off again for a project.

## Install

```bash
claude plugin install tenuo --marketplace tenuo-ai/tenuo-claude-code
```

Then open Claude Code in your project and run `/tenuo:setup`.

## Try it

Ask in your own words; Claude starts the matching skill and asks before it installs anything.

- "Limit Claude to this repo and keep a log of what it does."
- "Is Tenuo on in this project?"
- "What did Claude do here, and would my policy have stopped anything?"

| Skill | What it does |
|---|---|
| `/tenuo:setup` | Installs the `tenuo-claude` CLI, writes a starter policy, verifies the authorizer; checks and repairs an existing setup. |
| `/tenuo:status` | Shows whether this project is governed and whether it is observing or enforcing. Read-only. |
| `/tenuo:audit` | Shows and verifies the signed record of allowed and denied calls. Read-only. |

## What the plugin runs, installs, writes and sends

**Runs.** Three hooks (PreToolUse, PostToolUse, SessionStart) run `scripts/tenuo-hook`, a shell script that starts `scripts/tenuo_plugin.py`, a standard-library Python launcher. On every tool call the launcher looks for a `tenuo.yaml` in the project. With none it exits and does nothing. In a governed project it passes the call to the `tenuo-claude` CLI, which asks a Tenuo authorizer running on this machine whether the call fits your policy. The launcher makes no network calls. The three skills run the same launcher with a fixed set of read-only commands (`check`, `status`, `verify`, `audit`, `state-dir`, `--version`); it refuses anything else.

**Installs, during `/tenuo:setup` and only after you approve each command.**

- The `tenuo-claude-code` package from PyPI, with `uv tool install` or `pipx install`. Tenuo publishes it; its source is this repository.
- The `tenuo-authorizer` binary, a pinned release downloaded over HTTPS from the `tenuo-ai/tenuo` releases on GitHub into `~/.tenuo/bin`. If no prebuilt binary exists for the platform and `cargo` is installed, it is built from source instead.

**Writes.**

- In the project: `tenuo.yaml` (your policy), PreToolUse and PostToolUse hook entries in `.claude/settings.json`, and an MCP proxy entry in `.mcp.json` when the policy limits an MCP server.
- Outside the project: keys, the current warrant and the receipt log under `~/.tenuo/projects/<project>/`, and one marker file in the plugin's data directory so the setup hint is shown once.
- The receipt log holds, for each tool call, the tool name, its arguments, the decision and the reason, and the first 240 characters of the tool's result. It stays on your machine. `tenuo-claude uninstall` deletes it.

**Sends.** In local mode, nothing: the authorizer listens on `127.0.0.1` and no tool-call data leaves the machine. Cloud mode is separate and opt-in (`tenuo-claude bootstrap --cloud` with credentials for your own Tenuo Cloud tenant); it then sends receipts to that tenant and fetches warrants from it. See the [privacy policy](https://tenuo.ai/privacy).

**Changes to Claude Code settings.** Setup adds the two hook entries above to the project's `.claude/settings.json`. It does not change permission modes or allow rules. `tenuo-claude disable` removes the entries.

## Troubleshooting and removal

- `/tenuo:status` names the failing check and its fix. More cases: [docs/TROUBLESHOOTING.md](https://github.com/tenuo-ai/tenuo-claude-code/blob/main/docs/TROUBLESHOOTING.md).
- A governed project whose `tenuo-claude` CLI is missing denies tool calls until the CLI is back or you run `tenuo-claude disable`. This is deliberate: a broken setup must not fail open.
- `tenuo-claude disable` turns governance off for a project; `tenuo-claude uninstall` also deletes its keys and receipts. Removing the plugin alone does not remove hook entries the CLI wrote.
- Questions and bugs: [GitHub issues](https://github.com/tenuo-ai/tenuo-claude-code/issues). Security reports: [SECURITY.md](https://github.com/tenuo-ai/tenuo-claude-code/blob/main/SECURITY.md).

Full documentation: [tenuo-ai/tenuo-claude-code](https://github.com/tenuo-ai/tenuo-claude-code#readme). License: Apache-2.0.
