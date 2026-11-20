---
name: setup
description: Set up Tenuo for the current project, or check and repair an existing setup. Use when the user wants to limit what Claude or an MCP server can do (specific repos, folders, shell commands, web domains), wants a signed record of Claude's tool calls, or asks to install or set up Tenuo. Starts in observe-only mode, so nothing is blocked until the user turns enforcement on.
---

Tenuo checks each tool call against a policy the user owns, before the call runs, and keeps a signed record of what was allowed and denied. It is a command-line tool, `tenuo-claude`, plus hook entries it writes into the project's Claude Code settings. This skill sets it up. Every command below is an ordinary shell command the user sees and approves.

If the user did not type `/tenuo:setup` themselves, first say in two or three lines what setup will do here (install the `tenuo-claude` CLI and an authorizer program, write `tenuo.yaml` and hook entries in this project, start in observe-only mode) and wait for a yes before installing or writing anything.

## How to run commands here

- One plain command per call: no `&&`, `;`, pipes, redirects, shell variables or subshells.
- Each command costs the user an approval, so run only the ones listed in the steps. A fresh setup needs about five. Do not probe for other tools or guess at other install locations.
- Set up the user's project, never any other directory. Use the session's working directory as the project directory, as an absolute path; you already know it.
- Never display private keys or credential files, and do not write hook settings by hand.

## Steps

1. Find out what is already here.
   - Look for `tenuo.yaml`, `tenuo.cloud.yaml` and `tenuo.advanced.yaml` in the project directory with a file search. Do not open `tenuo.yaml`.
   - Run `tenuo-claude --version`. If it answers, `tenuo-claude` is the CLI from here on and step 2 is done.
   - If there is a Cloud overlay (`tenuo.cloud.yaml` or `tenuo.advanced.yaml`) but no `tenuo.yaml`, stop: report the unfinished Cloud setup and ask for the intended policy. A local bootstrap would move those files aside.
2. If the command was not found, run `uv tool install tenuo-claude-code`. It is safe to run when the package is already installed. Then run `uv tool dir --bin`; the CLI is the `tenuo-claude` in the directory it prints, and you use that full path from here on. Tell the user once that `uv tool update-shell` puts it on `PATH`. Only if `uv` itself is missing, try `pipx install tenuo-claude-code`; if neither exists, say that uv or pipx must be installed first and stop, without claiming setup succeeded. Use a persistent install, not `uvx`: the hooks need the program after this session.
3. Fresh project (no `tenuo.yaml`): say first that this downloads a native authorizer program, creates `tenuo.yaml`, keeps private state outside the project under `~/.tenuo`, and adds hook entries to the project's `.claude/settings.json`. Then run, with the project directory and the CLI from step 1:

   ```sh
   TENUO_PROJECT_DIR='<project directory>' <cli> bootstrap --native --pack filesystem-dev
   ```

   The filesystem-dev pack limits file access to the project directory, WebFetch to api.github.com, and the shell to `ls` and `pwd`. Describe the policy as it is; do not promise broad shell access. Other packs need their parameters reviewed first. Its output ends with the policy self-test (`VERIFY OK`). Continue at step 5.
4. Existing setup (`tenuo.yaml` is present): preserve the policy and its mode. Run `<cli> status`, then `<cli> check`, and repair only the problem they report, each as its own command tied to the project as in step 3:
   - no state yet (a policy that was never initialized on this machine): `init`, then `up`;
   - missing hook wiring, or a changed policy: `refresh`. Do not use `init` on an initialized project;
   - a stopped local authorizer, or an expired warrant that did not renew: `up`.

   Never use `--local`, overwrite the policy, or bootstrap an existing Cloud setup. Managed deployments belong to their administrator; do not replace them with a user-owned authorizer.
5. Confirm with `<cli> status`. Stop on errors and report the failed step; do not disable governance or broaden permissions to get a clean result. In a project that is already enforcing, the policy may deny these commands (the starter policy allows only `ls` and `pwd` in the shell). Do not retry or route around a denial: give the user the exact command to run in their own terminal.
6. Report in five lines or fewer: the project, the posture, authorizer and warrant status, and the outcome. Take the posture from `status`: say **Observing — actions are logged, not blocked** only when it shows `DRY-RUN — observe-only`, and **Enforcing — out-of-policy calls are blocked** only when it does not. Then give the next two steps: open a new Claude Code session in the project so the hooks load, and after some normal work ask "what did Claude do?" (or run `/tenuo:audit`) to see what the policy would have stopped.

Switch to `mode: enforce` only when the user asks for it, after they have reviewed the policy. They apply it with `tenuo-claude refresh`. Never demonstrate a block with a destructive command or a real secret. Local governance can be removed by the person who owns the machine; an organization that needs it to hold against that uses managed settings.
