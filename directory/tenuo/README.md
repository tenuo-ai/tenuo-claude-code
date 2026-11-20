# Tenuo for Claude Code

Give Claude Code real access and keep it in bounds. Tenuo limits each tool and MCP server to the repos, folders, shell commands and web domains you name, and keeps a signed record of every allowed and denied call.

This plugin is three skills that set Tenuo up in a project, show its status, and read its record. Tenuo itself is an open-source command-line tool, `tenuo-claude`, which the setup skill installs with your approval. It works with Claude Code on macOS and Linux.

## Try it

Ask in your own words; Claude starts the matching skill.

- "Limit Claude to this repo and keep a log of what it does."
- "Is Tenuo on in this project?"
- "What did Claude do here, and would my policy have stopped anything?"

| Skill | What it does |
|---|---|
| `/tenuo:setup` | Installs the `tenuo-claude` CLI, writes a starter policy and checks it works. Checks and repairs an existing setup. |
| `/tenuo:status` | Says whether this project is governed, and whether it is observing or enforcing. |
| `/tenuo:audit` | Shows and verifies the signed record of allowed and denied calls. |

## Nothing happens until you opt in

Installing this plugin does not limit, block or log anything. Tenuo acts only in a project where you ran setup, and setup starts in observe-only mode: calls are recorded, none are blocked. Blocking starts when you change the policy to `mode: enforce` yourself. `tenuo-claude disable` turns it off again for a project.

## What the plugin runs, installs, writes and sends

**The plugin itself** contains Markdown instructions and an icon. It has no hooks, no scripts and no programs, and it runs nothing by itself.

**The skills ask Claude to run commands**, each one an ordinary shell command that you see and approve:

- `/tenuo:setup` installs the `tenuo-claude-code` package from PyPI (with `uv tool install` or `pipx install`), then runs `tenuo-claude bootstrap`. Bootstrap downloads the `tenuo-authorizer` program, a pinned release from the `tenuo-ai/tenuo` releases on GitHub, into `~/.tenuo/bin`, and starts it on this machine.
- `/tenuo:status` runs `tenuo-claude status`, and `/tenuo:audit` runs `tenuo-claude audit --verify`.

**What setup writes.** In the project: `tenuo.yaml` (your policy), and PreToolUse and PostToolUse hook entries in `.claude/settings.json`, so that Claude Code asks Tenuo before each tool call. When the policy limits an MCP server, an entry in `.mcp.json`. Outside the project: keys, the current warrant and the record of decisions under `~/.tenuo/projects/`. It does not change permission modes or allow rules. `tenuo-claude disable` removes the hook entries; `tenuo-claude uninstall` also deletes the keys and the record.

**What is recorded.** For each tool call: the tool name, its arguments, the decision and the reason, and the first 240 characters of the tool's result. The record stays on your machine.

**What is sent.** In local mode Tenuo sends nothing: the authorizer listens on `127.0.0.1`. When you run `/tenuo:status` or `/tenuo:audit`, their output is shown to Claude and becomes part of your conversation like any other command output; to read the record without Claude, run `tenuo-claude audit --verify` in a terminal. Cloud mode is separate and opt-in, with credentials for your own Tenuo Cloud tenant. See the [privacy policy](https://tenuo.ai/privacy).

## Good to know

- Once a project is enforcing, the starter policy allows only `ls` and `pwd` in the shell, so Claude cannot run `tenuo-claude` there. The status and audit skills then tell you so and give you the command to run in your own terminal.
- Start a new Claude Code session after setup so the project's hooks load.
- A second edition of this plugin, installed from the project's own repository, adds hooks that keep a set-up project governed when its settings file is missing, and a status line at session start. Use one edition or the other: `claude plugin install tenuo --marketplace tenuo-ai/tenuo-claude-code`.

Documentation, troubleshooting and source: [tenuo-ai/tenuo-claude-code](https://github.com/tenuo-ai/tenuo-claude-code#readme). Questions and bugs: [GitHub issues](https://github.com/tenuo-ai/tenuo-claude-code/issues). License: Apache-2.0.
