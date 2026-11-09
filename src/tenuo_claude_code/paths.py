"""Project root discovery and path constants for tenuo-claude-code."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

__all__ = [
    "ADMIN_COMMAND",
    "ADMIN_COMMAND_LEGACY",
    "BIN_LAUNCHER",
    "CLI_COMMAND",
    "CLI_COMMAND_LEGACY",
    "PACKAGE_DIR",
    "bind_project_paths",
    "bundled_template",
    "default_policy_name",
    "find_project_root",
    "harness_tools_file",
    "legacy_state_dir",
    "project_state_dir",
    "scaffold_example_policy",
]

PACKAGE_DIR = Path(__file__).resolve().parent

CLI_COMMAND = "tenuo-claude"
CLI_COMMAND_LEGACY = "tenuo-claude-code"
ADMIN_COMMAND = "tenuo-admin"
ADMIN_COMMAND_LEGACY = "tenuo-claude-admin"
BIN_LAUNCHER = "tenuo-claude"


def find_project_root(start: Path | None = None, *, fallback_cwd: bool = False) -> Path:
    """Locate the directory containing ``tenuo.yaml`` (the governed project).

    Search order: ``TENUO_PROJECT_DIR`` env → walk up from *start* or cwd.
    When *fallback_cwd* is set and no policy is found, return the starting cwd
    (used by ``bootstrap`` / ``init`` in a fresh project directory).
    """
    env = os.environ.get("TENUO_PROJECT_DIR", "").strip()
    if env:
        root = Path(env).expanduser().resolve()
        if (root / "tenuo.yaml").is_file() or fallback_cwd:
            return root
        raise SystemExit(f"TENUO_PROJECT_DIR={env!r} has no tenuo.yaml")
    cur = (start or Path.cwd()).resolve()
    for directory in (cur, *cur.parents):
        if (directory / "tenuo.yaml").is_file():
            return directory
    if fallback_cwd:
        return cur
    raise SystemExit(
        "No tenuo.yaml in this directory or any parent — "
        "cd to your governed project, run `tenuo-claude bootstrap`, or set TENUO_PROJECT_DIR."
    )


def bundled_template(name: str) -> Path:
    """Shipped template bundled with the package (PyPI install)."""
    path = PACKAGE_DIR / "templates" / name
    if not path.is_file():
        raise SystemExit(f"Missing bundled template {name!r} — reinstall tenuo-claude-code")
    return path


_EXAMPLE_POLICY_HEADER = """\
# Example policy — written by `tenuo-claude bootstrap` (or `init` / `onboard`).
# Starter rules: sandbox-scoped Read, small Bash allowlist, default deny.
# Edit enforce, sandbox, and mode before production use.
#
"""

_DEFAULT_POLICY_NAME = "tenuo-claude"


def default_policy_name(project_root: Path) -> str:
    """Derive ``tenuo.yaml`` ``name:`` from the project directory basename."""
    raw = project_root.resolve().name.strip()
    if not raw or raw in {".", ".."}:
        return _DEFAULT_POLICY_NAME
    name = raw.lower().replace("_", "-").replace(" ", "-")
    name = re.sub(r"[^a-z0-9-]+", "-", name)
    name = re.sub(r"-+", "-", name).strip("-")
    return name[:64] if name else _DEFAULT_POLICY_NAME


def scaffold_example_policy(project_root: Path, *, no_scaffold: bool = False) -> bool:
    """Write ``tenuo.yaml`` and sandbox dir from the bundled example when missing.

    Returns True when a new example policy was created.
    """
    dest = project_root / "tenuo.yaml"
    if dest.is_file():
        return False
    if no_scaffold:
        raise SystemExit(
            f"Missing {dest.name} — add a policy file or run without --no-scaffold "
            "(bootstrap writes an example policy automatically)."
        )
    import yaml

    template = bundled_template("tenuo.yaml.example")
    cfg = yaml.safe_load(template.read_text(encoding="utf-8")) or {}
    cfg["name"] = default_policy_name(project_root)
    dest.write_text(_EXAMPLE_POLICY_HEADER + yaml.dump(cfg, default_flow_style=False, sort_keys=False),
                    encoding="utf-8")
    sandbox = cfg.get("sandbox", "./workspace")
    sandbox_path = project_root / sandbox
    sandbox_path.mkdir(parents=True, exist_ok=True)

    # Create a sample file in the sandbox for testing
    notes_file = sandbox_path / "notes.txt"
    if not notes_file.exists():
        notes_file.write_text(
            "# Project Notes\n\n"
            "This file is in the workspace directory and can be read by Claude Code.\n"
            "Files outside this directory are denied by the default policy.\n",
            encoding="utf-8"
        )

    print(f"Wrote example policy: {dest.name} (name: {cfg['name']})")
    print("  Starter rules only — edit enforce, sandbox, and mode before production use.")
    print(f"  Sandbox directory: {sandbox}")
    return True


def harness_tools_file() -> Path:
    """Bundled harness tool list (package data)."""
    return PACKAGE_DIR / "data" / "harness_tools.yaml"


def template_file(name: str, project_root: Path | None = None) -> Path:
    """Locate a shipped template (bundled, project dir, or repo ``templates/``)."""
    bundled = PACKAGE_DIR / "templates" / name
    if bundled.is_file():
        return bundled
    root = project_root or find_project_root()
    for directory in (root, root.parent):
        for sub in ("", "templates"):
            candidate = directory / sub / name if sub else directory / name
            if candidate.is_file():
                return candidate
    return root / "templates" / name


LEGACY_STATE_DIRNAME = ".state"


def legacy_state_dir(project_root: Path) -> Path:
    """Where state lived before it moved out of the project (``<project>/.state``)."""
    return project_root / LEGACY_STATE_DIRNAME


def home_state_dir(project_root: Path) -> Path:
    """Per-project state directory under ``~/.tenuo/projects``.

    Keys, warrant, gateway and receipts live outside the governed project so
    nothing scoped to the project tree (a recursive search included) can reach
    them. The name is the project basename plus a hash of its resolved path.
    """
    root = project_root.resolve()
    digest = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:12]
    return Path.home() / ".tenuo" / "projects" / f"{default_policy_name(root)}-{digest}"


def project_state_dir(project_root: Path) -> Path:
    """Resolve the state directory: ``TENUO_STATE_DIR`` → home → not-yet-migrated legacy.

    The home directory wins as soon as it exists, so a ``.state`` that appears in
    the project later is never picked up. A project initialized by an older
    release keeps working from ``<project>/.state`` until ``init``/``refresh``
    moves it.
    """
    override = os.environ.get("TENUO_STATE_DIR", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    home = home_state_dir(project_root)
    legacy = legacy_state_dir(project_root)
    if not home.is_dir() and (legacy / "state.json").is_file():
        return legacy
    return home


def bind_project_paths(module, *, fallback_cwd: bool = False) -> None:
    """Bind project-scoped path globals on *module* (typically ``cli``)."""
    root = find_project_root(fallback_cwd=fallback_cwd)
    module.DEMO_DIR = root
    module.STATE = project_state_dir(root)
    module.LEGACY_STATE = legacy_state_dir(root)
    module.CONFIG_FILE = root / "tenuo.yaml"
    module.CLOUD_PROFILE = root / "tenuo.cloud.yaml"
    module.ADVANCED_PROFILE = root / "tenuo.advanced.yaml"
    module.CLOUD_ENV_EXAMPLE = template_file("cloud.env.example", root)
    module.LAUNCHER = root / "bin" / BIN_LAUNCHER
    module.LAUNCHER_REL = f"./bin/{BIN_LAUNCHER}"
    module.HARNESS_TOOLS_FILE = harness_tools_file()
    module.HOLDER_KEY = module.STATE / "holder_key.b64"
    module.ISSUER_KEY = module.STATE / "issuer_key.b64"
    module.ISSUER_PUB = module.STATE / "issuer_pub.hex"
    module.RECEIPT_KEY = module.STATE / "receipt_key.b64"
    module.RECEIPT_PUB = module.STATE / "receipt_pub.hex"
    module.WARRANT = module.STATE / "warrant.b64"
    module.STATE_JSON = module.STATE / "state.json"
    module.GATEWAY = module.STATE / "gateway.yaml"
    module.SRL = module.STATE / "srl.cbor"
    module.RECEIPTS = module.STATE / "receipts.jsonl"
    module.CLOUD_ENV = module.STATE / "cloud.env"
    module.CLOUD_STATE = module.STATE / "cloud_state.json"
    module.AGENTS_DIRS = (root / ".claude" / "agents", Path.home() / ".claude" / "agents")
