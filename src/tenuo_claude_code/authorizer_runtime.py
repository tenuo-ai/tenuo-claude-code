"""Authorizer process lifecycle: Docker container or native ``tenuo-authorizer`` binary."""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Callable

import certifi

DEFAULT_IMAGE = "tenuo/authorizer:0.3.0"
DEFAULT_AUTHORIZER_PORT = 9090
AUTHORIZER_PORT_ENV = "TENUO_AUTHORIZER_PORT"
LEGACY_AUTHORIZER_PORT_ENV = "PORT"
RELEASE_REPO = "tenuo-ai/tenuo"
_INFO_VERSION_RE = re.compile(r"^Tenuo Authorizer v(\S+)", re.MULTILINE)
# Docker tags can't contain '+', so the authorizer's `+authz.N` semver build
# metadata is rendered as `-authz.N` in the image tag (e.g. `0.2.0-authz.2` is
# semver `0.2.0+authz.2`). Strip that suffix to recover the crate version while
# leaving genuine pre-release identifiers like `-beta.24` intact.
_TAG_BUILD_META_RE = re.compile(r"[-+]authz\.[0-9A-Za-z.-]+$")


def authorizer_port_env_hint() -> str:
    return f"set {AUTHORIZER_PORT_ENV} to another value"


def resolve_authorizer_port() -> int:
    """Loopback port for the local authorizer (``TENUO_AUTHORIZER_PORT``, else ``PORT``)."""
    for key in (AUTHORIZER_PORT_ENV, LEGACY_AUTHORIZER_PORT_ENV):
        raw = os.environ.get(key, "").strip()
        if raw:
            return int(raw)
    return DEFAULT_AUTHORIZER_PORT


def managed_install_root() -> Path:
    """User-local install root (``~/.tenuo``). Binaries live in ``bin/``."""
    return Path(os.environ.get("TENUO_INSTALL_ROOT", Path.home() / ".tenuo")).expanduser()


def managed_binary_path() -> Path:
    name = "tenuo-authorizer.exe" if platform.system().lower() == "windows" else "tenuo-authorizer"
    return managed_install_root() / "bin" / name


def authorizer_crate_version(image: str = DEFAULT_IMAGE) -> str:
    """Crate version for the pinned authorizer, matching what the binary reports.

    The image tag renders semver build metadata ``+authz.N`` as ``-authz.N`` (Docker
    tags forbid ``+``), so tag ``0.2.0-authz.2`` is crate ``0.2.0`` — which is what the
    authorizer's ``/status`` and ``crate_version_from_authorizer_version`` produce. A
    real pre-release like ``0.1.0-beta.24`` is preserved.
    """
    tag = image.rsplit(":", 1)[-1].lstrip("v")
    return _TAG_BUILD_META_RE.sub("", tag)


def release_tag(image: str = DEFAULT_IMAGE) -> str:
    version = authorizer_crate_version(image)
    return version if version.startswith("v") else f"v{version}"


def install_hint(image: str = DEFAULT_IMAGE) -> str:
    return "run: tenuo-claude install-authorizer"


def crate_version_from_authorizer_version(version: str) -> str:
    """Strip ``+authz.N`` build metadata from a full authorizer version string."""
    return version.split("+", 1)[0]


def parse_binary_version(info_output: str) -> str | None:
    match = _INFO_VERSION_RE.search(info_output)
    return match.group(1) if match else None


def query_binary_version(binary: Path) -> str | None:
    try:
        result = subprocess.run(
            [str(binary), "info"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if result.returncode != 0:
        return None
    return parse_binary_version(result.stdout)


def version_compatible(installed: str | None, pinned_crate: str) -> bool:
    if not installed:
        return True
    return crate_version_from_authorizer_version(installed) == pinned_crate


def ensure_binary_version(binary: Path, image: str = DEFAULT_IMAGE) -> str | None:
    """Fail (or warn) when the native binary crate version differs from the package pin."""
    installed = query_binary_version(binary)
    pinned = authorizer_crate_version(image)
    if installed is None:
        print("Warning: could not read tenuo-authorizer version (continuing)")
        return None
    if version_compatible(installed, pinned):
        return installed
    msg = (
        f"tenuo-authorizer {installed} does not match pinned {pinned}.\n"
        f"  • {install_hint(image)}\n"
        "  • Or set TENUO_AUTHORIZER_SKIP_VERSION=1 to override"
    )
    if os.environ.get("TENUO_AUTHORIZER_SKIP_VERSION", "").strip().lower() in ("1", "true", "yes"):
        print(f"Warning: {msg.replace(chr(10), ' ')}")
        return installed
    raise SystemExit(msg)


def runtime_meta_path(mount: Path) -> Path:
    return mount / "runtime.json"


def read_runtime_meta(mount: Path) -> dict:
    path = runtime_meta_path(mount)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def read_runtime_backend(mount: Path) -> str | None:
    backend = read_runtime_meta(mount).get("backend")
    return backend if isinstance(backend, str) else None


def write_runtime_meta(mount: Path, **fields: object) -> None:
    mount.mkdir(parents=True, exist_ok=True)
    data = read_runtime_meta(mount)
    data.update(fields)
    runtime_meta_path(mount).write_text(json.dumps(data, indent=2))


def clear_runtime_meta(mount: Path) -> None:
    runtime_meta_path(mount).unlink(missing_ok=True)


def _ssl_context() -> ssl.SSLContext:
    """TLS trust store — uses certifi so macOS/python.org venvs verify GitHub HTTPS."""
    return ssl.create_default_context(cafile=certifi.where())


def _urlopen(req: urllib.request.Request, *, timeout: float = 30):
    return urllib.request.urlopen(req, timeout=timeout, context=_ssl_context())


def _download_url(url: str, dest: Path) -> None:
    with _urlopen(urllib.request.Request(url)) as resp:
        dest.write_bytes(resp.read())


def platform_triple() -> str:
    machine = platform.machine().lower()
    arch = {"arm64": "aarch64", "amd64": "x86_64"}.get(machine, machine)
    system = platform.system().lower()
    if system == "darwin":
        return f"{arch}-apple-darwin"
    if system == "linux":
        return f"{arch}-unknown-linux-gnu"
    if system == "windows":
        return f"{arch}-pc-windows-msvc"
    raise RuntimeError(f"unsupported platform: {system}/{machine}")


def _github_release_assets(tag: str) -> list[dict]:
    url = f"https://api.github.com/repos/{RELEASE_REPO}/releases/tags/{tag}"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    with _urlopen(req) as resp:
        data = json.loads(resp.read().decode())
    return data.get("assets") or []


def _pick_release_asset(assets: list[dict], triple: str) -> dict | None:
    for asset in assets:
        name = asset.get("name") or ""
        if "tenuo-authorizer" not in name:
            continue
        if triple in name:
            return asset
    return None


def _extract_executable(archive: Path, dest: Path) -> None:
    name = archive.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            members = [m for m in zf.namelist() if "tenuo-authorizer" in m and not m.endswith("/")]
            if not members:
                raise RuntimeError(f"no tenuo-authorizer binary in {archive.name}")
            dest.write_bytes(zf.read(members[0]))
    elif name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive, "r:gz") as tf:
            members = [m for m in tf.getmembers() if "tenuo-authorizer" in m.name and m.isfile()]
            if not members:
                raise RuntimeError(f"no tenuo-authorizer binary in {archive.name}")
            extracted = tf.extractfile(members[0])
            if extracted is None:
                raise RuntimeError(f"could not extract {members[0].name}")
            dest.write_bytes(extracted.read())
    else:
        shutil.copy2(archive, dest)


def download_release_binary(image: str = DEFAULT_IMAGE) -> Path:
    """Download a prebuilt ``tenuo-authorizer`` from the tenuo core GitHub release."""
    dest = managed_binary_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    tag = release_tag(image)
    triple = platform_triple()
    asset = _pick_release_asset(_github_release_assets(tag), triple)
    if asset is None:
        raise FileNotFoundError(
            f"no prebuilt tenuo-authorizer for {triple} in {RELEASE_REPO} release {tag}"
        )
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / asset["name"]
        _download_url(asset["browser_download_url"], archive)
        if archive.name == dest.name or not archive.name.endswith((".tar.gz", ".tgz", ".zip")):
            shutil.copy2(archive, dest)
        else:
            _extract_executable(archive, dest)
    dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return dest


def cargo_available() -> bool:
    return shutil.which("cargo") is not None


def install_via_cargo(image: str = DEFAULT_IMAGE) -> Path:
    """Build and install ``tenuo-authorizer`` into ``~/.tenuo/bin`` via ``cargo install --root``."""
    if not cargo_available():
        raise RuntimeError("Rust toolchain not found (install from https://rustup.rs)")
    root = managed_install_root()
    root.mkdir(parents=True, exist_ok=True)
    version = authorizer_crate_version(image)
    cmd = [
        "cargo", "install", "tenuo", "--version", version,
        "--features", "data-plane,server", "--bin", "tenuo-authorizer", "--locked",
        "--root", str(root),
    ]
    print(f"Building tenuo-authorizer {version} (first install may take several minutes)…")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        raise RuntimeError("cargo install failed")
    dest = managed_binary_path()
    if not dest.is_file():
        raise RuntimeError(f"cargo install finished but {dest} is missing")
    return dest


def install_authorizer(image: str = DEFAULT_IMAGE, *, force: bool = False) -> Path:
    """Install ``tenuo-authorizer`` to ``~/.tenuo/bin``: prebuilt release, else ``cargo install --root``."""
    dest = managed_binary_path()
    pinned = authorizer_crate_version(image)
    if not force and dest.is_file():
        installed = query_binary_version(dest)
        if installed and version_compatible(installed, pinned):
            return dest
    try:
        print(f"Downloading tenuo-authorizer {pinned}…")
        return download_release_binary(image)
    except (urllib.error.URLError, FileNotFoundError, RuntimeError) as exc:
        print(f"Prebuilt download unavailable ({exc}).")
    return install_via_cargo(image)


def find_authorizer_binary(image: str = DEFAULT_IMAGE) -> Path | None:
    """Best-effort lookup: override → ``~/.tenuo/bin`` → PATH."""
    override = os.environ.get("TENUO_AUTHORIZER_BIN", "").strip()
    if override:
        path = Path(override).expanduser()
        return path if path.is_file() else None
    managed = managed_binary_path()
    if managed.is_file():
        return managed
    found = shutil.which("tenuo-authorizer")
    return Path(found) if found else None


def resolve_authorizer_binary(image: str = DEFAULT_IMAGE, *, install: bool = False) -> Path:
    """Locate ``tenuo-authorizer`` (override → managed → PATH), optionally installing first."""
    if install:
        install_authorizer(image)
    override = os.environ.get("TENUO_AUTHORIZER_BIN", "").strip()
    if override:
        path = Path(override).expanduser()
        if not path.is_file():
            raise SystemExit(f"TENUO_AUTHORIZER_BIN={override!r} not found")
        return path
    managed = managed_binary_path()
    if managed.is_file():
        return managed
    found = shutil.which("tenuo-authorizer")
    if found:
        return Path(found)
    raise SystemExit(
        "Could not find tenuo-authorizer.\n"
        f"  • {install_hint(image)}\n"
        "  • Or install Docker and run `tenuo-claude up --docker`\n"
        "  • Or set TENUO_AUTHORIZER_BIN to an existing binary"
    )


def docker_ok() -> tuple[bool, str]:
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        return False, "Docker not installed"
    except subprocess.TimeoutExpired:
        return False, "Docker not responding"
    if r.returncode != 0:
        tail = (r.stderr or r.stdout or "").strip().splitlines()
        return False, tail[-1] if tail else "docker info failed"
    return True, "Docker daemon running"


def choose_backend(args, *, force_native: bool = False) -> str:
    if getattr(args, "native", False) and getattr(args, "docker", False):
        raise SystemExit("Use only one of --native or --docker")
    if getattr(args, "docker", False):
        return "docker"
    if force_native or getattr(args, "native", False):
        return "native"
    env = os.environ.get("TENUO_AUTHORIZER_BACKEND", "").strip().lower()
    if env in ("native", "process"):
        return "native"
    if os.environ.get("TENUO_AUTHORIZER_NATIVE", "").strip().lower() in ("1", "true", "yes"):
        return "native"
    ok, _ = docker_ok()
    return "native" if not ok else "docker"


def port_listening(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) == 0


def fetch_health(authz_url: str) -> dict | None:
    try:
        with urllib.request.urlopen(authz_url + "/health", timeout=2) as resp:
            data = json.loads(resp.read().decode())
            return data if isinstance(data, dict) else None
    except Exception:
        return None


def fetch_health_unix(socket_path: str) -> dict | None:
    """Check /health over a Unix domain socket using a raw HTTP/1.1 request."""
    import http.client

    class _UnixHTTPConnection(http.client.HTTPConnection):
        def __init__(self, socket_path: str) -> None:
            super().__init__("localhost")
            self._socket_path = socket_path

        def connect(self) -> None:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect(self._socket_path)

    try:
        conn = _UnixHTTPConnection(socket_path)
        conn.timeout = 2
        conn.request("GET", "/health")
        resp = conn.getresponse()
        data = json.loads(resp.read().decode())
        conn.close()
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def is_tenuo_authorizer_health(authz_url: str) -> bool:
    health = fetch_health(authz_url)
    return bool(health and health.get("service") == "tenuo-authorizer")


def is_tenuo_authorizer_health_unix(socket_path: str) -> bool:
    health = fetch_health_unix(socket_path)
    return bool(health and health.get("service") == "tenuo-authorizer")


def assert_port_available(port: int, authz_url: str, mount: Path) -> None:
    """Raise if the loopback port is taken by a foreign or unmanaged process."""
    if not port_listening("127.0.0.1", port):
        return
    if is_tenuo_authorizer_health(authz_url):
        if native_process_alive(mount):
            return
        raise SystemExit(
            f"127.0.0.1:{port} already serves tenuo-authorizer but is not managed by "
            f"this project (stale PID or manual start). Stop it, run `tenuo-claude down`, "
            f"or {authorizer_port_env_hint()}."
        )
    raise SystemExit(
        f"127.0.0.1:{port} is already in use by another process. "
        f"Free the port or {authorizer_port_env_hint()}."
    )


def native_pid_path(mount: Path) -> Path:
    return mount / "native.pid"


def native_log_path(state: Path) -> Path:
    return state / "authorizer.log"


def native_process_alive(mount: Path) -> bool:
    """True if the native authorizer PID file points at a live process."""
    pid_file = native_pid_path(mount)
    if not pid_file.is_file():
        return False
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        pid_file.unlink(missing_ok=True)
        return False


def native_running(mount: Path, authz_url: str) -> bool:
    if not native_process_alive(mount):
        return False
    try:
        with urllib.request.urlopen(authz_url + "/health", timeout=2):
            return True
    except Exception:
        return False


def stop_native(mount: Path, *, timeout_s: float = 5.0) -> bool:
    pid_file = native_pid_path(mount)
    if not pid_file.is_file():
        return False
    pid: int | None = None
    try:
        pid = int(pid_file.read_text().strip())
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (ProcessLookupError, OSError, ValueError):
        pid_file.unlink(missing_ok=True)
        clear_runtime_meta(mount)
        return True
    deadline = time.time() + timeout_s
    while time.time() < deadline and pid is not None:
        try:
            os.kill(pid, 0)
        except OSError:
            break
        time.sleep(0.2)
    else:
        if pid is not None:
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except (ProcessLookupError, OSError, ValueError):
                pass
    pid_file.unlink(missing_ok=True)
    clear_runtime_meta(mount)
    return True


def start_native(
    *,
    binary: Path,
    mount: Path,
    gateway_name: str,
    port: int,
    authz_url: str,
    denv: dict[str, str],
    srl_name: str | None,
    state: Path,
    image: str = DEFAULT_IMAGE,
    socket_path: str | None = None,
) -> None:
    """Start the native authorizer process.

    When *socket_path* is provided the authorizer is launched with
    ``--socket <socket_path>`` and does not bind any TCP port.  The caller is
    responsible for passing a matching ``authz_url`` (ignored in socket mode;
    health is checked via the socket).
    """
    gw = mount / gateway_name
    if not gw.is_file():
        raise SystemExit(f"Missing {gw} — run `tenuo-claude init` first.")
    if socket_path is None:
        # TCP mode: ensure the port is free before starting.
        assert_port_available(port, authz_url, mount)
    ensure_binary_version(binary, image)
    stop_native(mount)
    # Scoped environment: pass only what the authorizer process needs.
    # Starting from os.environ would leak unrelated shell secrets into a
    # long-lived network service; Docker mode already limits to denv only.
    _ALLOWLIST = {
        "PATH", "HOME", "TMPDIR", "TMP", "TEMP",
        # TLS CA bundles — needed on some Linux distros / NixOS / corporate MITM
        "SSL_CERT_FILE", "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
        "NIX_SSL_CERT_DATA",
        # macOS system locale (avoids Popen locale warnings)
        "LC_ALL", "LANG",
    }
    env: dict[str, str] = {k: v for k, v in os.environ.items() if k in _ALLOWLIST}
    env.update(denv)
    if srl_name and (mount / srl_name).is_file():
        env["TENUO_REVOCATION_LIST"] = str((mount / srl_name).resolve())
    log_path = native_log_path(state)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if socket_path is not None:
        cmd = [
            str(binary), "serve",
            "--config", str(gw.resolve()),
            "--socket", socket_path,
        ]
    else:
        cmd = [
            str(binary), "serve",
            "--config", str(gw.resolve()),
            "--port", str(port),
            "--bind", "127.0.0.1",
        ]
    with log_path.open("a", encoding="utf-8") as logfh:
        logfh.write(f"\n--- native authorizer start {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} ---\n")
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=logfh,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    native_pid_path(mount).write_text(str(proc.pid))
    meta: dict[str, object] = {"backend": "native", "binary": str(binary.resolve())}
    if socket_path is not None:
        meta["socket"] = socket_path
    write_runtime_meta(mount, **meta)


def wait_healthy(
    authz_url: str,
    *,
    is_running: Callable[[], bool],
    on_exited: Callable[[], None] | None = None,
    timeout_s: float = 20.0,
    socket_path: str | None = None,
) -> None:
    """Poll until the authorizer reports healthy or the process exits.

    When *socket_path* is provided, health is checked over the Unix socket
    rather than TCP.
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            if socket_path is not None:
                healthy = fetch_health_unix(socket_path) is not None
            else:
                with urllib.request.urlopen(authz_url + "/health", timeout=2):
                    healthy = True
            if healthy:
                return
        except Exception:
            healthy = False
        if not healthy:
            if not is_running():
                if on_exited:
                    on_exited()
                raise SystemExit("Authorizer exited during startup")
            time.sleep(0.5)
    raise SystemExit("Authorizer didn't become healthy in time")
