# Managed mode (enterprise / MDM)

Managed Cloud mode makes the **Cloud trigger the sole authority**: the authorizer
trusts only the tenant cloud root, local policy can only attenuate, and the
posture is pinned to `enforce`. The `tenuo-claude` CLI enforces this for a
cooperative developer (fail-closed `up`, honest `status`/`check`). To enforce it
against a **non-cooperative** developer you must deploy two things at a tier the
developer cannot override:

1. **Claude Code managed settings** that pin the Tenuo hook and disable bypass.
2. **A system-pinned authorizer** whose trust anchor is the cloud root only.

Both are generated for you (the hook command is machine-specific, so a
hand-written file is the #1 footgun):

```bash
# Linux fleet (systemd / Docker authorizer):
tenuo-claude managed-template --out ./tenuo-managed --platform linux \
  --hook-python /opt/tenuo/venv/bin/python        # administrator-owned virtualenv

# Hardened Linux fleet: only members of the `tenuo` group can connect to the
# root-owned authorizer socket. The default is easier rollout: root-owned socket,
# mode 0666.
tenuo-claude managed-template --out ./tenuo-managed --platform linux \
  --hook-python /opt/tenuo/venv/bin/python \
  --socket-group tenuo

# macOS fleet (native authorizer):
tenuo-claude managed-template --out ./tenuo-managed --platform macos \
  --hook-python /opt/tenuo/venv/bin/python \
  --authorizer-bin /opt/tenuo/bin/tenuo-authorizer   # baked into the launchd plist
```

`--platform {all,linux,macos}` scopes the OS service artifact so a Linux rollout
does not get the macOS plist (and its native-binary warning), and a macOS rollout
does not get the Docker/systemd unit. The default is `all`. Generate a single
artifact to stdout with `--target {claude-settings,managed-mcp,systemd,launchd,env}`.

## Artifacts

| File | Purpose |
|------|---------|
| `managed-settings.json` | Pins the PreToolUse/PostToolUse hook; `allowManagedHooksOnly`, `allowManagedPermissionRulesOnly`, `disableBypassPermissionsMode`, `disableAutoMode`, and (if MCP is configured) `allowManagedMcpServersOnly` lock out local overrides. |
| `managed-mcp.json` | The Tenuo proxy as the sole admin-deployed MCP server (only when `mcp.downstream` is set). |
| `tenuo-authorizer.service` | systemd unit: runs the authorizer with `TENUO_TRUSTED_KEYS` = cloud root **only**, pinned image (version floor). |
| `com.tenuo.authorizer.plist` | macOS launchd equivalent. |
| `authorizer.env` | Runtime (service-account) key, **never** an admin key. Root-owned, `chmod 0600`. |

## Where managed settings live (highest precedence)

These outrank user, project, and command-line settings and cannot be overridden:

| OS | Path |
|----|------|
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.json` |
| Linux / WSL | `/etc/claude-code/managed-settings.json` |
| Windows | `C:\Program Files\ClaudeCode\managed-settings.json` |

(You can also deliver them via the Claude admin console or an MDM plist/registry
policy; see Claude Code's admin docs.)

## Deploy

```bash
# Claude side (pick the path for the OS):
sudo install -d -m 0755 -o root /etc/claude-code
sudo cp managed-settings.json "/etc/claude-code/managed-settings.json"
sudo cp managed-mcp.json       "/etc/claude-code/managed-mcp.json"   # if generated

# Authorizer side:
sudo install -d -m 0755 -o root /etc/tenuo /etc/tenuo/gateway
sudo install -m 0600 -o root authorizer.env /etc/tenuo/authorizer.env
sudo install -m 0644 -o root "$(tenuo-claude state-dir)/gateway.yaml" /etc/tenuo/gateway/gateway.yaml  # routes (no keys)

# Linux (Docker-backed authorizer), default path:
sudo cp tenuo-authorizer.service /etc/systemd/system/
sudo systemctl enable --now tenuo-authorizer

# macOS (NATIVE authorizer, see note below):
sudo cp com.tenuo.authorizer.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.tenuo.authorizer.plist
```

Only if you generated with `--socket-group tenuo` (hardened, group-connectable
`0660` socket), create the group and add each developer **before** starting the
service above:

```bash
sudo groupadd --system tenuo 2>/dev/null || true
sudo usermod -aG tenuo "$DEVELOPER_USER"   # repeat via MDM / user provisioning
```

Before deploying, replace the loud placeholders in the service/env files:

- `REPLACE_WITH_TENANT_ROOT_HEX`: the tenant cloud root (the trust anchor; the
  CLI prints it on `tenuo-claude status` in Cloud mode, and `tenuo-admin` knows it).
- `REPLACE_WITH_CONTROL_PLANE_URL` and `REPLACE_WITH_RUNTIME_KEY`.
- `REPLACE_WITH_AUTHORIZER_BINARY` (macOS plist only): the path to the native
  authorizer binary. Pass `--authorizer-bin /opt/tenuo/bin/tenuo-authorizer` (or set
  `authorizer.binary` in `tenuo.yaml`) at generation time to bake it in; the CLI
  warns only when the path is left unresolved.

## Rollout checklist

1. Publish policy from a security-owned environment with `tenuo-admin setup
   --managed`; developers should never receive a tenant-admin key.
2. Generate artifacts with `tenuo-claude managed-template --platform linux|macos
   --hook-python /opt/tenuo/venv/bin/python`. For hardened Linux rollout, add
   `--socket-group tenuo` and provision that group (create it and add each
   governed user) before starting the authorizer service, and before users
   launch Claude, since the group controls socket connect permission.
3. Replace `REPLACE_WITH_TENANT_ROOT_HEX`, `REPLACE_WITH_CONTROL_PLANE_URL`, and
   `REPLACE_WITH_RUNTIME_KEY`. Use a runtime/service-account key only.
4. Deploy `managed-settings.json` through Claude Enterprise, MDM, or the OS managed
   settings path. Confirm `allowManagedHooksOnly`, `allowManagedPermissionRulesOnly`,
   `disableBypassPermissionsMode`, and `disableAutoMode` remain present.
5. Deploy `/etc/tenuo/authorizer.env` as root-owned `0600` and
   `/etc/tenuo/gateway/gateway.yaml` as root-owned `0644`.
6. Start the system authorizer and verify the socket:

   ```bash
   sudo systemctl restart tenuo-authorizer
   systemctl status tenuo-authorizer --no-pager
   sudo ls -ld /var/run/tenuo
   sudo ls -l /var/run/tenuo/authorizer.sock
   tenuo-claude check
   ```

   Default rollout should show a root-owned socket with mode `srw-rw-rw-`. Hardened
   rollout should show a root-owned socket in the configured group with mode
   `srw-rw----`.
7. Start in Cloud `dry-run`, review `WOULD-DENY` receipts, then switch the Cloud
   policy to `enforce`. Managed endpoints pin local posture to enforcement once the
   Cloud policy is enforcing.

## Why both halves are required

The pinned hook ensures every tool call is checked and cannot be bypassed. The
system-pinned authorizer ensures the *decision* is made against a cloud-root-only
trust anchor, so a developer cannot substitute a permissive local authorizer and
self-sign warrants. Deploy only the Claude settings and the hook has no trusted
decision service; deploy only the authorizer and a user can remove the hook.
Managed mode needs both.

The pinned managed hook (`_managed-hook` / `_managed-mcp-proxy`) also forces
`enforce` regardless of local `mode:`/flag edits, ignores the editable
`<state>/state.json` `authorizer_url` override, and reaches the authorizer over a
**root-owned Unix socket** (never loopback TCP), so a user-controlled substitute
cannot answer.

## How the hook authenticates the authorizer

Loopback TCP cannot authenticate the responder: if the system authorizer is down,
any local process can bind `127.0.0.1:<port>` and answer `allow`. The managed hook
closes that with OS file ownership instead of a port. It connects to a Unix socket
(default `/var/run/tenuo/authorizer.sock`) and, before trusting any response,
verifies the socket is a real socket (not a symlink), owned by root (or the
configured service user), under a **root-owned, non-world-writable** directory. An
unprivileged user cannot create or replace such a socket, so a passing check means
the responder is the privileged service. Anything else **fails closed to deny**.

Managed mode will not silently fall back to TCP: a developer who launches Claude
with `TENUO_AUTHZ_TRANSPORT=tcp` is ignored. The only way back to loopback TCP is a
**root-owned break-glass marker** (`/etc/tenuo/allow_insecure_tcp`): a file an
admin must place, not an env var a user can set.

## Serving the authorizer on the socket

The generated units run the authorizer with `serve --socket
/var/run/tenuo/authorizer.sock` and **no published TCP port**. There is no loopback
surface to race. The directory is created root-owned, `0755`, before the daemon
starts (systemd `RuntimeDirectory=tenuo`; launchd wrapper `mkdir`).

On Linux the authorizer image's default user is uid `1000`, which **cannot** create a
socket inside that root-owned `0755` directory (it fails at bind with `PermissionDenied`,
`Os code 13`). The generated Docker unit therefore runs the container as root
(`docker run -u 0:0 …`) so it can create the socket and the bind-mounted socket is
**root-owned on the host**, the ownership the hook's check trusts. (A `1000`-owned
socket directory would be unsafe on a typical workstation where the developer is also
uid `1000` and could replace the socket.) On macOS the native launchd daemon already
runs as root.

**Connect permission vs. ownership.** A root-owned socket is created mode `0660` by
default, which the unprivileged Claude hook cannot `connect()` to. The generated units
therefore pass `--socket-mode 0666`: the socket stays **root-owned** (the trust anchor:
only root could place it under the root-owned dir), but any local user may connect.
This does not weaken the model: the authorizer authorizes by warrant/PoP, not by socket
peer identity, so connecting without a valid warrant just gets denied. To tighten,
generate with `tenuo-claude managed-template --socket-group tenuo` and put governed
developers in that group; the generated service keeps the socket root-owned and uses
mode `0660`.

**Linux vs macOS: different backends on purpose.** Linux runs the authorizer in
Docker: a container-created Unix socket on a bind mount is usable by the host (same
kernel). macOS Docker Desktop runs the container inside a Linux VM, so a socket it
creates is **not** a macOS-kernel socket the Claude hook can connect to; a
Docker-backed macOS rollout would fail closed. The macOS plist therefore runs a
**native host authorizer** (`REPLACE_WITH_AUTHORIZER_BINARY` / `authorizer.binary`)
that owns the macOS socket directly.

This requires an authorizer build that supports `serve --socket` / `--socket-mode`
(the pinned `tenuo/authorizer` image does). If you are still on an older TCP-only
authorizer, place the **root-owned break-glass marker** to keep managed mode working
on loopback TCP in the interim:

```bash
sudo install -m 0600 -o root /dev/null /etc/tenuo/allow_insecure_tcp
```

That falls back to loopback TCP, which **cannot authenticate the responder**, so
treat the always-running, root-owned authorizer service as required, and remove the
marker as soon as the socket endpoint is live.

The hook interpreter must belong to a dedicated root-owned virtualenv, including installed dependencies and ancestor directories, with no group/world write access. Install the package there before generating templates; project-local or user-owned launchers are rejected. See [the 0.7.0 migration notes](../../docs/releases/0.7.0.md).
