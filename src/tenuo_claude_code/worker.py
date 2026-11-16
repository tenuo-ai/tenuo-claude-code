"""Let a Hermes agent elsewhere hand coding tasks to Claude Code on this machine.

This machine is the authority. Its owner grants Hermes a standing, limited
permission once; Hermes can only narrow it per task, and this machine checks
every job against its own key:

    tenuo-claude worker grant --to <Hermes's key> --share ~/code --days 7
    tenuo-claude worker --hermes http://hermes.example:9931      # token in $CLAUDE_WORKER_TOKEN
    tenuo-claude worker revoke                                   # stops everything at once

``grant`` signs a warrant with this machine's key, held by Hermes's key: read and
edit files inside ``--share``, run the listed git and test commands, and push
only to branches matching ``--push`` (default ``claude/*``) on ``origin``. Hermes
asks its owner in chat, then narrows that grant to one folder, the commands the
owner chose, one branch and a few minutes, and hands it back as a job.

The worker dials out (this machine opens no port), waits for jobs, and for each:

1. checks the job's warrant chains to this machine's own key, through the
   current grant (not a revoked one), to this machine as holder;
2. creates the job's branch, runs Claude Code under ``tenuo-claude run`` rules
   (every tool call is checked against the narrowed warrant and receipted);
3. if the warrant allows it, pushes that one branch itself (Claude never pushes);
4. sends back a fixed-shape report, signed by this machine: status, branch,
   commit ids, counts and the receipt head. With ``--report full`` the grant
   also lets Claude's own words and the denied calls go back.

The key lives in ``~/.tenuo/claude-worker/<name>.key`` and never leaves this
machine. Ctrl-C stops the worker; nothing runs without it.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import run

KEY_DIR = Path("~/.tenuo/claude-worker").expanduser()
FILE_CAPS = ("read_file", "write_file", "edit_file", "glob", "grep")
DEFAULT_COMMANDS = (
    "git status", "git diff", "git log", "git show", "git add", "git commit",
    "git restore", "git rm", "git mv", "git ls-files", "git grep",
    "pytest", "python -m pytest", "python3 -m pytest", "python -m unittest",
    "python3 -m unittest", "npm test", "go test", "cargo test",
)
COMMAND_RE = re.compile(r"[A-Za-z0-9_./:=+-]+( [A-Za-z0-9_./:=+-]+)*")
BRANCH_RE = re.compile(r"[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*")
REPORTS = ("summary", "full")
# git, run by the worker itself: no repo hooks, no pager, no prompts.
GIT = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat"]


# ---------------------------------------------------------------------------
# Keys and the standing grant
# ---------------------------------------------------------------------------


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


def grant_path(name: str) -> Path:
    return KEY_DIR / f"{name}.grant.json"


def revoked_path(name: str) -> Path:
    return KEY_DIR / f"{name}.revoked"


def command_pattern(prefix: str) -> str:
    return r"(?s)^" + r"\ ".join(re.escape(w) for w in prefix.split()) + r"( .*)?$"


def command_constraint(commands: list[str]):
    """One program from the list, literal arguments, and one of the listed prefixes."""
    import tenuo_core
    from tenuo import All, AnyOf, Regex

    binaries = sorted({c.split()[0] for c in commands})
    return All([tenuo_core.Shlex(allow=binaries), AnyOf([Regex(command_pattern(c)) for c in commands])])


def mint_standing_grant(key, *, to: str, share: Path, commands: list[str], push: str | None,
                        remote: str, days: float, report: str) -> dict:
    """Sign the standing grant (this machine → Hermes) and describe it."""
    from tenuo import Exact, Pattern, Subpath, Warrant

    if report not in REPORTS:
        raise ValueError(f"--report must be one of {', '.join(REPORTS)}")
    for c in commands:
        if not COMMAND_RE.fullmatch(c):
            raise ValueError(f"command {c!r} must be plain words (no shell syntax)")
        if c.split()[:2] == ["git", "push"]:
            raise ValueError("git push is never a command; use --push to let the worker push")
    if push is not None and not re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._*/-]*", push):
        raise ValueError("--push must look like claude/*")
    root = str(share.resolve())
    builder = Warrant.mint_builder()
    for cap in FILE_CAPS:
        builder = builder.capability(cap, {"path": Subpath(root)})
    if commands:
        builder = builder.capability(run.TOOL_DEFAULTS["Bash"][0], {"command": command_constraint(commands)})
    if push:
        builder = builder.capability("git_push", {"remote": Exact(remote), "branch": Pattern(push)})
    warrant = builder.holder(run.public_key(to)).ttl(int(days * 86400)).mint(key)
    return {"warrant": warrant.to_base64(), "id": warrant.id, "to": to.strip(), "share": root,
            "commands": commands, "push": push, "remote": remote, "report": report,
            "expires_at": str(warrant.expires_at())}


def load_grant(name: str) -> dict | None:
    """The current standing grant, or None when there is none, it was revoked, or it expired."""
    try:
        grant = json.loads(grant_path(name).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    if grant.get("id") in revoked_ids(name):
        return None
    from tenuo import Warrant
    if Warrant.from_base64(grant["warrant"]).is_expired():
        return None
    return grant


def revoked_ids(name: str) -> set[str]:
    try:
        return set(revoked_path(name).read_text().split())
    except FileNotFoundError:
        return set()


def grant_info(grant: dict) -> str:
    """What Hermes may show and pre-check: the grant's terms, not secrets."""
    info = {k: grant[k] for k in ("id", "share", "commands", "push", "remote", "report", "expires_at")}
    return base64.b64encode(json.dumps(info, separators=(",", ":")).encode()).decode()


# ---------------------------------------------------------------------------
# A job
# ---------------------------------------------------------------------------


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


def check_job(job: dict, *, key, grant: dict | None, revoked: set[str]) -> tuple[Path, list]:
    """Refuse a job unless it narrows this machine's current grant, for this machine, in the share."""
    from tenuo import Authorizer

    if grant is None:
        raise ValueError("this machine has no current grant for Hermes (tenuo-claude worker grant)")
    chain = run.decode_chain(job["warrant"])
    if chain[0].id in revoked:
        raise ValueError("the grant this job uses was revoked")
    if chain[0].id != grant["id"]:
        raise ValueError("the job doesn't use this machine's current grant")
    Authorizer(trusted_roots=[key.public_key]).verify_chain(chain)  # signed by us, narrowed, unexpired
    if chain[-1].authorized_holder.to_bytes() != key.public_key.to_bytes():
        raise ValueError("the warrant is not held by this machine's key")
    return folder_in_share(Path(grant["share"]), job.get("folder", "")), chain


def push_allowed(chain: list, key, remote: str, branch: str) -> tuple[bool, str]:
    """Check ``git_push`` for this branch against the chain, with proof of possession."""
    from tenuo import Authorizer

    args = {"remote": remote, "branch": branch}
    try:
        pop = chain[-1].sign(key, "git_push", args, int(time.time()))
        Authorizer(trusted_roots=[key.public_key]).check_chain(chain, "git_push", args, bytes(pop))
        return True, "within grant"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc) or type(exc).__name__


def git(folder: Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(GIT + list(args), cwd=folder, capture_output=True, text=True,
                          timeout=120, stdin=subprocess.DEVNULL,
                          env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    if check and proc.returncode:
        raise RuntimeError((proc.stderr or proc.stdout).strip()[-300:] or f"git {args[0]} failed")
    return proc.stdout.strip()


REPORT_TOOL = "claude_report"


def sign_report(key, report: dict, chain: list | None) -> dict:
    """The report with a Tenuo proof: signed by this machine as holder of the job's warrant.

    Hermes checks it with ``tenuo_core.verify_meta`` over the same argument JSON. A job
    refused before its warrant checked out has no chain, so its report is unsigned.
    """
    import tenuo_core
    from tenuo.meta import argument_json

    body = {k: v for k, v in report.items() if k != "proof"}
    if not chain:
        return body
    ts = int(time.time())
    env = tenuo_core.sign_meta(chain, key, REPORT_TOOL, argument_json(body), ts)
    return {**body, "proof": {"warrant": env["warrant"], "signature": env["signature"], "ts": ts}}


def report_for(summary: dict, *, mode: str, branch: str | None, pushed: bool,
               commits: list[dict], push_error: str | None) -> dict:
    """The fixed-shape report. ``full`` adds Claude's own words and the denied calls."""
    receipts = summary.get("receipts") or {}
    report = {
        "ok": bool(summary.get("ok")) and not push_error,
        "error": summary.get("error") or push_error,
        "branch": branch,
        "pushed": pushed,
        "commits": [c["id"] for c in commits],
        "allowed": summary.get("allowed") or 0,
        "denied_count": len(summary.get("denied") or []),
        "receipts": {k: receipts.get(k) for k in ("count", "head", "chain_ok", "signed_by")},
        "grant": (summary.get("grant") or {}).get("grant_id"),
        "warrant": (summary.get("grant") or {}).get("warrant_id"),
        "report": mode,
    }
    if mode == "full":
        report["result"] = summary.get("result")
        report["denied"] = summary.get("denied") or []
        report["commit_subjects"] = commits
    return report


class Hermes:
    def __init__(self, url: str, name: str, token: str, key):
        self.url, self.name, self.token, self.key = url.rstrip("/"), name, token, key
        self.grant: dict | None = None

    def _request(self, method: str, path: str, body: dict | None = None, timeout: float = 40):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Authorization": f"Bearer {self.token}", "X-Tenuo-Machine": self.name,
                   "X-Tenuo-Public-Key": public_key_b64(self.key), "Content-Type": "application/json"}
        if self.grant:
            headers.update({"X-Tenuo-Root": self.grant["share"], "X-Tenuo-Grant": self.grant["warrant"],
                            "X-Tenuo-Grant-Info": grant_info(self.grant)})
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
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

    def result(self, job_id: str, report: dict) -> None:
        for attempt in range(5):
            try:
                self._request("POST", f"/claude/jobs/{job_id}/result", report, timeout=20)
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


def handle(hermes: Hermes, job: dict, *, name: str, claude: str | None) -> dict:
    job_id = str(job.get("id") or "")
    key = hermes.key
    grant = load_grant(name)
    branch = job.get("branch") or None
    try:
        folder, chain = check_job(job, key=key, grant=grant, revoked=revoked_ids(name))
        if branch is not None:
            if not isinstance(branch, str) or not BRANCH_RE.fullmatch(branch) or ".." in branch:
                raise ValueError(f"branch {branch!r} is not a plain branch name")
            ok, why = push_allowed(chain, key, grant["remote"], branch)
            if not ok:
                raise ValueError(f"pushing {branch} is outside this machine's grant ({why})")
            git(folder, "rev-parse", "--git-dir")
            remote_url = git(folder, "remote", "get-url", grant["remote"])
            if git(folder, "status", "--porcelain"):
                raise ValueError(f"{folder.name} has uncommitted changes; commit or stash them first")
            base = git(folder, "rev-parse", "HEAD")
            start_branch = git(folder, "rev-parse", "--abbrev-ref", "HEAD")
            if git(folder, "branch", "--list", branch):
                raise ValueError(f"{folder.name} already has a branch {branch}; ask for another name")
            git(folder, "switch", "-c", branch)
    except Exception as exc:  # noqa: BLE001
        report = sign_report(key, {"ok": False, "error": f"refused by the machine: {exc}", "report": "summary"},
                             None)
        hermes.result(job_id, report)
        print(f"✗ job {job_id} refused: {exc}")
        return report
    print(f"→ job {job_id}: {folder}" + (f" on {branch}" if branch else ""))
    state = KEY_DIR / "runs" / job_id
    holder = base64.b64encode(bytes(key.secret_key_bytes())).decode()

    def on_receipt(row: dict) -> None:
        line = progress_line(row)
        if line:
            print("  " + line)
            hermes.progress(job_id, line)

    def should_stop() -> str | None:
        return "the machine's owner revoked the grant" if chain[0].id in revoked_ids(name) else None

    summary = run.execute(state, warrant=job["warrant"], holder_key=holder,
                          trusted_roots=[public_key_b64(key)], workspace=folder,
                          prompt=str(job.get("task") or ""), model=job.get("model"),
                          timeout=int(job.get("minutes") or 15) * 60, claude=claude,
                          on_receipt=on_receipt, revoked_file=str(revoked_path(name)),
                          should_stop=should_stop)
    pushed, commits, push_error = False, [], None
    if branch is not None:
        try:
            log = git(folder, "log", "--format=%h %s", f"{base}..{branch}")
            commits = [{"id": line.split(" ", 1)[0], "subject": line.split(" ", 1)[-1]}
                       for line in log.splitlines() if line.strip()]
            if commits and summary.get("ok") and not should_stop():
                ok, why = push_allowed(chain, key, grant["remote"], branch)
                run._append_receipt(state, {"tool": "worker", "cap": "git_push", "ts": int(time.time()),
                                            "args": {"remote": grant["remote"], "branch": branch},
                                            "warrant_id": chain[-1].id,
                                            "decision": "allow" if ok else "deny", "reason": why}, key)
                if not ok:
                    raise RuntimeError(f"push refused: {why}")
                hermes.progress(job_id, f"⬆️ git push {grant['remote']} {branch}")
                git(folder, "push", "--no-verify", remote_url, f"refs/heads/{branch}:refs/heads/{branch}")
                pushed = True
        except Exception as exc:  # noqa: BLE001
            push_error = f"push failed: {exc}"
        finally:
            if start_branch and start_branch != "HEAD":
                git(folder, "switch", start_branch, check=False)
                if not commits:
                    # Nothing to keep: remove the branch this job created, so the name can be reused.
                    git(folder, "branch", "-D", branch, check=False)
        rows, chain_ok = run.read_receipts(state, public_key_b64(key))
        summary["receipts"] = {**(summary.get("receipts") or {}), "count": len(rows),
                               "head": rows[-1]["hash"] if rows else None, "chain_ok": chain_ok}
    report = sign_report(key, report_for(summary, mode=grant.get("report", "summary"), branch=branch,
                                         pushed=pushed, commits=commits, push_error=push_error),
                         chain)
    print(f"← job {job_id}: {'ok' if report['ok'] else report.get('error')}"
          + (f", pushed {branch}" if pushed else ""))
    hermes.result(job_id, report)
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def cmd_grant(args) -> int:
    key = machine_key(args.name)
    share = Path(args.share).expanduser()
    if not share.is_dir():
        print(f"{share} is not a folder", file=sys.stderr)
        return 2
    commands = [" ".join(c.split()) for c in (args.command or DEFAULT_COMMANDS)]
    try:
        grant = mint_standing_grant(key, to=args.to, share=share, commands=commands,
                                    push=None if args.no_push else args.push, remote=args.remote,
                                    days=args.days, report=args.report)
    except ValueError as exc:
        print(f"grant refused: {exc}", file=sys.stderr)
        return 2
    path = grant_path(args.name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(grant, fh, indent=2)
    print(f"Granted Hermes ({grant['to'][:12]}…) until {grant['expires_at']}:")
    print(f"  folders inside {grant['share']}: read and edit")
    print(f"  commands: {', '.join(commands) or 'none'}")
    print(f"  push: {'only ' + grant['remote'] + ' ' + grant['push'] if grant['push'] else 'never'}")
    print(f"  report back: {grant['report']}")
    print(f"Grant {grant['id']}. A running worker picks it up on its next poll; "
          f"`tenuo-claude worker revoke` ends it.")
    return 0


def cmd_revoke(args) -> int:
    grant = None
    try:
        grant = json.loads(grant_path(args.name).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    if grant is None:
        print("No grant to revoke.")
        return 0
    KEY_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(revoked_path(args.name), "a") as fh:
        fh.write(grant["id"] + "\n")
    grant_path(args.name).unlink(missing_ok=True)
    print(f"Revoked {grant['id']}. Any job using it is stopped now; Hermes can't start new ones.")
    return 0


def cmd_status(args) -> int:
    key = machine_key(args.name)
    print(f"This machine's key ({args.name}): {public_key_b64(key)}")
    grant = load_grant(args.name)
    if grant is None:
        print("No current grant. Give Hermes one with: tenuo-claude worker grant --to <Hermes's key> --share DIR")
        return 0
    print(f"Grant {grant['id']} to {grant['to'][:12]}… until {grant['expires_at']}")
    print(f"  share {grant['share']}; push {grant['push'] or 'never'}; report {grant['report']}")
    print(f"  commands: {', '.join(grant['commands'])}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tenuo-claude worker", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--name", default="laptop", help="this machine's name in Hermes (default: %(default)s)")
    sub = p.add_subparsers(dest="action")
    g = sub.add_parser("grant", help="give Hermes a standing, limited grant on this machine")
    g.add_argument("--to", required=True, help="Hermes's public key (Hermes shows it: /claude key)")
    g.add_argument("--share", required=True, help="the folder whose subfolders Hermes may ask about")
    g.add_argument("--command", action="append",
                   help="a command prefix Claude Code may run; repeatable (default: git basics and test runners)")
    g.add_argument("--push", default="claude/*", help="branches the worker may push (default: %(default)s)")
    g.add_argument("--no-push", action="store_true", help="never push")
    g.add_argument("--remote", default="origin", help="the remote pushes go to (default: %(default)s)")
    g.add_argument("--days", type=float, default=7, help="how long the grant lasts (default: %(default)s)")
    g.add_argument("--report", choices=REPORTS, default="summary",
                   help="what goes back to Hermes: summary (status, branch, commit ids, counts) or "
                        "full (also Claude's answer and denied calls). Default: %(default)s")
    sub.add_parser("revoke", help="end the current grant now, stopping any running job")
    sub.add_parser("status", help="show this machine's key and current grant")
    p.add_argument("--show-key", action="store_true", help="print this machine's public key and exit")
    p.add_argument("--hermes", help="the Hermes address the worker dials, e.g. http://hermes.example:9931")
    p.add_argument("--token-env", default="CLAUDE_WORKER_TOKEN",
                   help="environment variable holding the worker token (default: %(default)s)")
    p.add_argument("--claude", help="path to the claude binary")
    p.add_argument("--once", action="store_true", help="handle one job, then exit")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.action == "grant":
        return cmd_grant(args)
    if args.action == "revoke":
        return cmd_revoke(args)
    if args.action == "status":
        return cmd_status(args)
    key = machine_key(args.name)
    if args.show_key:
        print(public_key_b64(key))
        return 0
    token = os.environ.get(args.token_env, "")
    if not args.hermes or not token:
        print("needs " + ", ".join((["--hermes"] if not args.hermes else [])
                                   + ([f"${args.token_env}"] if not token else [])), file=sys.stderr)
        return 2
    hermes = Hermes(args.hermes, args.name, token, key)
    hermes.grant = load_grant(args.name)
    if hermes.grant is None:
        print("No current grant: Hermes can't send jobs until you run `tenuo-claude worker grant`.")
    else:
        print(f"Working for {args.hermes} as {args.name!r} under grant {hermes.grant['id']} "
              f"(share {hermes.grant['share']}). Ctrl-C stops it.")
    backoff = 1
    while True:
        hermes.grant = load_grant(args.name)
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
            handle(hermes, job, name=args.name, claude=args.claude)
            if args.once:
                return 0


if __name__ == "__main__":
    sys.exit(main())
