---
name: setup
description: Set up Tenuo for the current project, or check and repair an existing setup. Use when the user wants to limit what Claude or an MCP server can do (specific repos, folders, shell commands, web domains), wants a signed record of Claude's tool calls, or asks to install or set up Tenuo. Starts in observe-only mode, so nothing is blocked until the user turns enforcement on.
allowed-tools: Bash(python3 "${CLAUDE_PLUGIN_ROOT}/scripts/tenuo_plugin.py" run *)
---

Current state, from the plugin launcher (`tenuo-claude status` when a policy exists):

```
!`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/tenuo_plugin.py" run status`
```

If the user did not type `/tenuo:setup` themselves, first say in two or three
lines what setup will do here (install the `tenuo-claude` CLI and an authorizer
binary, write `tenuo.yaml` and hook settings in this project, start in
observe-only mode) and wait for a yes before installing or writing anything.

Set up Tenuo in the user's project, never in the plugin installation directory.
Installing this plugin alone does not activate governance. Keep the existing
plugin hooks and launcher intact: they defer to CLI-wired project hooks to avoid
duplicate decisions. Do not write hook settings by hand.

## How to run commands here

A fresh setup should cost the user two approvals: the install and the bootstrap.

- Read-only checks go through the launcher. It is pre-approved, finds the CLI
  even when it is not on `PATH`, and runs it in the project root. Copy it
  exactly, quotes included, and change only the last word:

  ```sh
  python3 "${CLAUDE_PLUGIN_ROOT}/scripts/tenuo_plugin.py" run check
  ```

  It accepts `check`, `status`, `verify`, `state-dir`, `audit` and `--version`,
  and refuses anything that changes state.
- One plain command per call: no `&&`, `;`, pipes, redirects, shell variables
  or subshells. Each of those is refused or adds an approval.
- Do not probe the environment, the home directory or the state directory with
  shell commands. The launcher output above already says whether a policy
  exists and where, whether the CLI is installed and where, and whether Cloud
  credentials exist. Never display private keys or credential files.
- Commands that change something (`uv tool install`, `bootstrap`, `init`,
  `refresh`, `up`) run as ordinary commands with the CLI path the launcher
  printed, so the user sees and approves each one.

## Steps

1. Read the launcher output above and pick the case.
   - **`No tenuo.yaml … Tenuo is not set up here`**: a fresh project. Go to
     step 2. If it also says Cloud credentials exist, stop: report the
     unfinished Cloud setup and ask for the intended policy instead of
     bootstrapping in local mode.
   - **A `Plugin:` line that names a project root**: an existing setup. Go to
     step 4. If that root is not the directory the user means, ask before
     changing anything.
   - **`tool calls will be denied until this is fixed`**: say calls are being
     denied and give the fix the line names (for example a `TENUO_PROJECT_DIR`
     that points at a directory without a policy). Stop there.
2. Install the CLI when the output says `not installed`:
   `uv tool install tenuo-claude-code` (or `pipx install tenuo-claude-code`
   when pipx is what the machine has). If neither installer exists, say that uv
   or pipx must be installed first; do not claim setup succeeded. Use a
   persistent install, not `uvx`: the hooks need the executable after this
   session. Do not replace an existing development install. Then run the
   launcher with `--version`; its output gives the CLI's full path. If that
   path is not on `PATH`, tell the user once that `uv tool update-shell` adds it.
3. Bootstrap a fresh local project. Say first that this installs a native
   authorizer, creates `tenuo.yaml`, keeps private state outside the project
   under `~/.tenuo`, and merges hook and MCP settings into the project. Then
   run, with the CLI path from step 2:

   ```sh
   <cli-path> bootstrap --native --pack filesystem-dev
   ```

   The filesystem-dev pack limits file access to the project directory,
   WebFetch to api.github.com, and the shell to `ls` and `pwd`. Describe the
   rendered policy as it is; do not promise broad shell access. Other packs
   need their parameters reviewed first. Leave `TENUO_PROJECT_DIR` unset until
   the policy exists. Continue at step 5.
4. Existing setup: preserve the policy and its mode. Run the launcher with
   `check`, then repair only the reported problem:
   - no state directory yet (a policy that was never initialized on this
     machine): `init`, then `up`;
   - an initialized project with missing hook wiring, or a changed policy:
     `refresh`. It rewrites the wiring and keeps the issuer key. Do not use
     `init` here: it mints a new issuer key and warrant, which a running
     authorizer does not trust. If the `Plugin:` line says the project is
     governed via the Tenuo plugin, unwired hooks are expected; change nothing;
   - a stopped local authorizer, or an expired warrant that did not renew: `up`.

   Never use `--local`, overwrite the policy, or bootstrap an existing Cloud
   setup. Managed deployments require their administrator's
   service/configuration; do not replace them with a user-owned authorizer.
5. Verify with the launcher: `check`, `verify`, then `status`. These check
   on-disk state and the authorizer, not whether this session loaded the hooks.
   Stop on errors and report the failed step; do not disable governance or
   broaden permissions to get a green result. In a project that is already
   enforcing, the policy may deny these commands (the starter policy allows
   only `ls` and `pwd` in the shell). Do not retry or route around a denial:
   give the user the exact command to run in their own terminal.
6. Report in five lines or fewer: the project, the posture, authorizer and
   warrant status, and the verification outcome. Take the posture from
   `status`, not from `mode:` in `tenuo.yaml`: a managed project is enforced
   even when the file says dry-run (`posture : enforce (pinned by org)`). Say
   **Observing — actions are logged, not blocked** only when status shows
   `DRY-RUN — observe-only`. Say **Enforcing — out-of-policy governed calls are
   blocked** only when checks pass and status does not show dry-run. Then give
   the next two steps: open a new Claude Code session in the project so the
   project hooks load, and after some normal work ask "what did Claude do?"
   (or run `/tenuo:audit`) to see what the policy would have stopped.

Switch to `mode: enforce` only when the user requests it, after reviewing the
policy. Apply with `refresh`, then `verify` and `status`. Never demonstrate a
block using a destructive command or a real secret. Local governance is removable
by the machine owner; tamper-resistant organizational deployment needs managed
settings and protected authorizer infrastructure.
