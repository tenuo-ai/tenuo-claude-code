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
        settings = dict(line.split("=", 1) for line in (environment / "pyvenv.cfg").read_text().splitlines() if "=" in line)
        settings = {key.strip().lower(): value.strip().lower() for key, value in settings.items()}
        if settings.get("include-system-site-packages", "false") != "false":
            raise ValueError("system-site inheritance is not supported in the managed runtime")
        _trusted_path(environment)
        _trusted_path(interpreter)
        for directory, dirs, files in os.walk(environment):
            for name in [*dirs, *files]:
                path = Path(directory) / name
                if path.is_symlink() and path.is_dir():
                    # Linux venvs commonly link lib64 to lib. Internal targets
                    # are inspected through their real path by this same walk.
                    path.resolve(strict=True).relative_to(environment.resolve(strict=True))
                _trusted_path(path)
                if path.suffix == ".egg-link":
                    raise ValueError(f"editable install {path} is not supported in the managed runtime")
                if path.suffix == ".pth" and path.is_file():
                    for line in path.read_text().splitlines():
                        line = line.rstrip()
                        if not line or line.startswith("#"):
                            continue
                        # Executable .pth code can install arbitrary import hooks;
                        # do not execute it to discover its targets during validation.
                        if line.startswith(("import ", "import\t")):
                            raise ValueError(f"executable .pth file {path} is not supported in the managed runtime")
                        target = (path.parent / line).resolve(strict=True)
                        target.relative_to(environment.resolve(strict=True))
                        _trusted_path(target)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Untrusted managed hook runtime: {exc}. "
                         "Install tenuo-claude-code in a root-owned venv and pass "
                         "--hook-python /opt/tenuo/venv/bin/python.") from exc
    return str(interpreter)
