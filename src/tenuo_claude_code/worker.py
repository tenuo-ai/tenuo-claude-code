"""Let a Hermes agent elsewhere hand coding tasks to Claude Code on this machine.

    tenuo-claude worker --show-key
    tenuo-claude worker --hermes https://hermes.example:9931 --name laptop \\
        --share ~/code --trusted-root <Hermes's key> --token-env CLAUDE_WORKER_TOKEN

The worker dials out to Hermes (this machine opens no port) and waits for jobs.
Hermes sends a job only after its owner approved it in chat. Each job carries a
warrant that Hermes signed for this machine's own key, for one folder inside
``--share``. Before starting Claude Code the worker checks that the warrant
chains to ``--trusted-root``, names this machine's key as holder, and covers
only a folder inside ``--share``. Claude Code then runs under ``tenuo-claude
run`` rules: every tool call is checked against the warrant before it runs.

The machine key lives in ``~/.tenuo/claude-worker/<name>.key`` and never leaves
this machine. Stop the worker with Ctrl-C; nothing runs without it.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import run

KEY_DIR = Path("~/.tenuo/claude-worker").expanduser()


def machine_key(name: str):
    """This machine's signing key for ``name``, created on first use (0600)."""
    from tenuo import SigningKey

    path = KEY_DIR / f"{name}.key"
    if path.exists():
        return SigningKey.from_bytes(base64.b64decode(path.read_text().strip()))
    KEY_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = SigningKey.generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(base64.b64encode(bytes(key.secret_key_bytes())).decode())
    return key


def public_key_b64(key) -> str:
    return base64.b64encode(key.public_key.to_bytes()).decode()


def folder_in_share(share: Path, folder: str) -> Path:
    """The job's folder, resolved, if it is inside the shared folder. Raises ValueError."""
    if not isinstance(folder, str) or not folder or folder.startswith("/") or ".." in folder.split("/"):
        raise ValueError(f"folder {folder!r} must be a relative path inside the shared folder")
    root = share.resolve()
    path = (root / folder).resolve()
    if path != root and root not in path.parents:
        raise ValueError(f"folder {folder!r} is outside the shared folder")
    if not path.is_dir():
        raise ValueError(f"{path} is not a folder")
    return path


def check_job(job: dict, *, key, share: Path, trusted_root: str) -> Path:
    """Refuse a job unless its warrant is Hermes's, held by this machine, for this folder."""
    if job.get("issuer") and job["issuer"].strip() != trusted_root.strip():
        raise ValueError("the job was signed by a key this worker doesn't trust")
    chain = run.decode_chain(job["warrant"])
    leaf = chain[-1]
    if leaf.authorized_holder.to_bytes() != key.public_key.to_bytes():
        raise ValueError("the warrant is not held by this machine's key")
    return folder_in_share(share, job.get("folder", ""))


class Hermes:
    def __init__(self, url: str, name: str, token: str, key, share: Path):
        self.url, self.name, self.token, self.key, self.share = url.rstrip("/"), name, token, key, share

    def _request(self, method: str, path: str, body: dict | None = None, timeout: float = 40):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "X-Tenuo-Machine": self.name,
            "X-Tenuo-Root": str(self.share.resolve()), "X-Tenuo-Public-Key": public_key_b64(self.key),
            "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)

    def next_job(self):
        status, body = self._request("GET", "/claude/next")
        return body if status == 200 else None

    def progress(self, job_id: str, line: str) -> None:
        try:
            self._request("POST", f"/claude/jobs/{job_id}/progress", {"line": line}, timeout=10)
        except Exception:  # noqa: BLE001 - progress is best effort
            pass

    def result(self, job_id: str, summary: dict) -> None:
        for attempt in range(5):
            try:
                self._request("POST", f"/claude/jobs/{job_id}/result", summary, timeout=20)
                return
            except Exception as exc:  # noqa: BLE001
                print(f"  could not send the result ({exc}); retrying", file=sys.stderr)
                time.sleep(2 * (attempt + 1))


def progress_line(row: dict) -> str | None:
    tool = row.get("tool") or ""
    if tool in run.HARNESS_TOOLS:
        return None
    arg = next(iter((row.get("args") or {}).values()), "")
    if isinstance(arg, str) and arg.startswith("/"):
        arg = os.path.basename(arg) or arg
    mark = "✅" if row.get("decision") == "allow" else "⛔"
    return f"{mark} {tool} {str(arg)[:80]}".rstrip()


def handle(hermes: Hermes, job: dict, *, trusted_root: str, claude: str | None) -> dict:
    job_id = str(job.get("id") or "")
    try:
        folder = check_job(job, key=hermes.key, share=hermes.share, trusted_root=trusted_root)
    except Exception as exc:  # noqa: BLE001
        summary = {"ok": False, "error": f"refused by the machine: {exc}"}
        hermes.result(job_id, summary)
        return summary
    print(f"→ job {job_id}: {folder} for {job.get('minutes')} min")
    state = KEY_DIR / "runs" / job_id
    holder = base64.b64encode(bytes(hermes.key.secret_key_bytes())).decode()

    def on_receipt(row: dict) -> None:
        line = progress_line(row)
        if line:
            print("  " + line)
            hermes.progress(job_id, line)

    summary = run.execute(state, warrant=job["warrant"], holder_key=holder,
                          trusted_roots=[trusted_root], workspace=folder, prompt=str(job.get("task") or ""),
                          model=job.get("model"), timeout=int(job.get("minutes") or 15) * 60,
                          claude=claude, on_receipt=on_receipt)
    print(f"← job {job_id}: {'ok' if summary.get('ok') else summary.get('error')}")
    hermes.result(job_id, summary)
    return summary


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tenuo-claude worker", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--name", default="laptop", help="this machine's name in Hermes (default: %(default)s)")
    p.add_argument("--show-key", action="store_true", help="print this machine's public key and exit")
    p.add_argument("--hermes", help="the Hermes address the worker dials, e.g. https://hermes.example:9931")
    p.add_argument("--share", help="the folder Hermes may ask Claude Code to work in (subfolders only)")
    p.add_argument("--trusted-root", help="Hermes's public key for Claude Code grants")
    p.add_argument("--token-env", default="CLAUDE_WORKER_TOKEN",
                   help="environment variable holding the worker token (default: %(default)s)")
    p.add_argument("--claude", help="path to the claude binary")
    p.add_argument("--once", action="store_true", help="handle one job, then exit")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    key = machine_key(args.name)
    if args.show_key:
        print(public_key_b64(key))
        return 0
    missing = [f for f in ("hermes", "share", "trusted_root") if not getattr(args, f)]
    token = os.environ.get(args.token_env, "")
    if missing or not token:
        print("needs " + ", ".join([f"--{m.replace('_', '-')}" for m in missing]
                                   + ([f"${args.token_env}"] if not token else [])), file=sys.stderr)
        return 2
    share = Path(args.share).expanduser()
    if not share.is_dir():
        print(f"{share} is not a folder", file=sys.stderr)
        return 2
    hermes = Hermes(args.hermes, args.name, token, key, share)
    print(f"Sharing {share.resolve()} with {args.hermes} as {args.name!r}. Ctrl-C stops it.")
    backoff = 1
    while True:
        try:
            job = hermes.next_job()
            backoff = 1
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:200]
            print(f"Hermes refused this worker ({exc.code}): {detail}", file=sys.stderr)
            if exc.code in (401, 403):
                return 1
            time.sleep(min(backoff, 30))
            backoff *= 2
            continue
        except Exception as exc:  # noqa: BLE001 - network blips: retry
            print(f"cannot reach Hermes ({exc}); retrying", file=sys.stderr)
            time.sleep(min(backoff, 30))
            backoff *= 2
            continue
        if job:
            handle(hermes, job, trusted_root=args.trusted_root, claude=args.claude)
            if args.once:
                return 0


if __name__ == "__main__":
    sys.exit(main())
