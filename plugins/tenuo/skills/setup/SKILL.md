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
plugin hooks and launcher intact: they defer to CLI-wired project hooks to avoid duplicate decisions. Do not write hook settings by hand.

1. Resolve the intended project directory from the session. Check whether
   `TENUO_PROJECT_DIR` or a parent `tenuo.yaml` points elsewhere; resolve ambiguity
   with the user before writing. Run in the resolved project directory. Once a
   policy exists, use an absolute, shell-quoted project path in `TENUO_PROJECT_DIR` for Tenuo commands.
2. Locate `tenuo-claude` and inspect `--version` and `bootstrap --help`. If absent,
   use `uv tool install tenuo-claude-code` (or `pipx install tenuo-claude-code` when
   pipx is available). If neither installer exists, explain that uv or pipx must
   be installed first; do not claim setup succeeded. Use a persistent installation,
   not `uvx`: hooks need a stable executable after this session. If the installed
   CLI lacks the documented flags, upgrade with its original installer before
   proceeding. Do not silently replace an existing development installation.
3. Check for `tenuo.yaml` and Cloud overlays (`tenuo.cloud.yaml`,
   `tenuo.advanced.yaml`). Resolve the state path with `tenuo-claude state-dir`
   (honor `TENUO_STATE_DIR`); check only the existence of `cloud.env` and
   `cloud_state.json` there and in legacy `.state/`. Never display private keys
   or credential files.
   - For an existing policy, preserve it and its mode. Run `tenuo-claude check`
     and `tenuo-claude status`. Repair only the reported problem:
     - no state directory yet (a policy that was never initialized on this
       machine): `init`, then `up`;
     - an initialized project with missing hook wiring, or a changed policy:
       `refresh`. It rewrites the wiring and keeps the issuer key. Do not use
       `init` here: it mints a new issuer key and warrant, which a running
       authorizer does not trust. If the `Plugin:` line says the project is
       governed via the Tenuo plugin, unwired hooks are expected; change nothing;
     - a stopped local authorizer: `up`.

     Never use `--local`, overwrite the policy, or bootstrap an existing Cloud
     setup. Managed deployments require their administrator's
     service/configuration; do not replace them with a user-owned authorizer.
   - If Cloud artifacts exist without a policy, report the incomplete setup and
     obtain the intended policy instead of resetting to local mode.
   - For a fresh local project, explain that setup installs a native authorizer,
     creates `tenuo.yaml` and private state outside the project, and merges
     project hook/MCP settings. Start in observation mode. Run:

     ```sh
     tenuo-claude bootstrap --native --pack filesystem-dev
     ```

     Run bootstrap from the resolved project directory. For a brand-new project,
     leave `TENUO_PROJECT_DIR` unset in the Claude session until the policy exists:
     the plugin intentionally fails closed when it points to a missing policy.
     The filesystem-dev pack defaults to the project directory, WebFetch to
     api.github.com, and Bash to ls/pwd. Review the rendered policy rather than
     promising broad shell access. Other packs require reviewing parameters first.
4. Run `tenuo-claude check`, `tenuo-claude verify`, and `tenuo-claude status`.
   These check on-disk state and the authorizer, not whether current hooks loaded.
   Stop on errors and report the failed step; do not disable governance or
   broaden permissions to get a green result. In a project that is already
   enforcing, the policy may deny these commands (the starter policy allows only
   `ls` and `pwd` in the shell). Do not retry or route around a denial: give the
   user the exact command to run in their own terminal.
5. Report the project, posture, authorizer and warrant status, and verification
   outcome. Take the posture from `tenuo-claude status`, not from `mode:` in
   `tenuo.yaml`: a managed project is enforced even when the file says dry-run
   (`posture : enforce (pinned by org)`). Say **Observing — actions are logged,
   not blocked** only when status shows `DRY-RUN — observe-only`. Say
   **Enforcing — out-of-policy governed calls are blocked** only when checks
   pass and status does not show dry-run. Tell the user to open a new Claude Code session in the
   project so changed project hooks load, then use `/tenuo:audit` after normal
   work. The CLI self-test alone does not prove this session loaded the hooks.

Switch to `mode: enforce` only when the user requests it, after reviewing the
policy. Apply with `refresh`, then `verify` and `status`. Never demonstrate a
block using a destructive command or a real secret. Local governance is removable
by the machine owner; tamper-resistant organizational deployment needs managed
settings and protected authorizer infrastructure.
