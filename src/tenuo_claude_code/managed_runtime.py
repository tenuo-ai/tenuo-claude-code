"""Trust checks for the administrator-owned Python environment used by managed hooks."""
from __future__ import annotations

import os
from pathlib import Path


def _trusted_path(path: Path) -> None:
    # Check both the named path and the symlink target, including ancestors: a
    # root-owned file in a user-writable directory can still be replaced.
    for candidate in (path.absolute(), path.resolve(strict=True)):
        for item in (candidate, *candidate.parents):
            info = item.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError(f"{item} must be root-owned and not group/world-writable")


def validate_managed_python(python: str) -> str:
    """Require a dedicated, root-owned venv, including installed dependencies.

    The administrator is responsible for the contents of this installation.
    Isolated Python startup excludes project imports, user site and PYTHONPATH.
    """
    if os.name != "posix":
        raise SystemExit("Managed hooks require a POSIX host (use WSL on Windows)")
    interpreter = Path(python).absolute()
    environment = interpreter.parent.parent
    try:
        if not (environment / "pyvenv.cfg").is_file():
            raise ValueError("use a dedicated administrator-owned virtualenv")
        _trusted_path(environment)
        _trusted_path(interpreter)
        for directory, dirs, files in os.walk(environment):
            for name in [*dirs, *files]:
                path = Path(directory) / name
                if path.is_symlink() and path.is_dir():
                    raise ValueError(f"directory symlink {path} is not supported in the managed runtime")
                _trusted_path(path)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Untrusted managed hook runtime: {exc}. "
                         "Install tenuo-claude-code in a root-owned venv and pass "
                         "--hook-python /opt/tenuo/venv/bin/python.") from exc
    return str(interpreter)
