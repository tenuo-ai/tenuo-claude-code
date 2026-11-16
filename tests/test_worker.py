"""`tenuo-claude worker`: Claude Code on this machine, for jobs a Hermes agent sends."""

import base64

import pytest

from tenuo_claude_code import worker


def _b64(raw):
    return base64.b64encode(bytes(raw)).decode()


def _setup(tmp_path, monkeypatch, **kw):
    """This machine (key + standing grant to a Hermes key) and Hermes's key."""
    from tenuo import SigningKey
    monkeypatch.setattr(worker, "KEY_DIR", tmp_path / "keys")
    share = tmp_path / "share"
    (share / "repo").mkdir(parents=True)
    mine, hermes = worker.machine_key("mac"), SigningKey.generate()
    grant = worker.mint_standing_grant(mine, to=_b64(hermes.public_key.to_bytes()), share=share,
                                       commands=kw.get("commands", ["git status", "git commit"]),
                                       push=kw.get("push", "claude/*"), remote="origin", days=1,
                                       report=kw.get("report", "summary"))
    worker.grant_path("mac").write_text(__import__("json").dumps(grant))
    return mine, hermes, grant, share


def _narrow(grant, hermes, holder_pub, *, folder, branch="claude/x", ttl=300, caps=None):
    """What Hermes does: narrow the standing grant to one folder and one branch."""
    from tenuo import Exact, Subpath, Warrant
    import tenuo_core
    root = Warrant.from_base64(grant["warrant"])
    caps = caps or {"read_file": {"path": Subpath(grant["share"] + "/" + folder)},
                    "git_push": {"remote": Exact("origin"), "branch": Exact(branch)}}
    leaf = root.attenuate(caps, hermes, ttl_seconds=ttl, holder=holder_pub)
    return {"id": "j1", "warrant": tenuo_core.encode_warrant_stack([root, leaf]), "folder": folder,
            "minutes": 5, "branch": branch}


def test_folder_must_be_inside_the_share(tmp_path):
    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "link").symlink_to("/etc")
    assert worker.folder_in_share(tmp_path, "repo") == (tmp_path / "repo").resolve()
    for bad in ("../x", "/etc", "", "repo/link", "missing"):
        with pytest.raises(ValueError):
            worker.folder_in_share(tmp_path, bad)


def test_check_job(tmp_path, monkeypatch):
    from tenuo import SigningKey
    mine, hermes, grant, share = _setup(tmp_path, monkeypatch)
    job = _narrow(grant, hermes, mine.public_key, folder="repo")
    folder, chain = worker.check_job(job, key=mine, grant=grant, revoked=set())
    assert folder == (share / "repo").resolve() and len(chain) == 2
    with pytest.raises(ValueError, match="held by this machine"):
        worker.check_job(_narrow(grant, hermes, SigningKey.generate().public_key, folder="repo"),
                         key=mine, grant=grant, revoked=set())
    with pytest.raises(ValueError, match="revoked"):
        worker.check_job(job, key=mine, grant=grant, revoked={grant["id"]})
    with pytest.raises(ValueError, match="no current grant"):
        worker.check_job(job, key=mine, grant=None, revoked=set())
    with pytest.raises(ValueError, match="outside|relative"):
        worker.check_job({**job, "folder": "../.."}, key=mine, grant=grant, revoked=set())


def test_a_job_not_rooted_in_this_machine_is_refused(tmp_path, monkeypatch):
    """Hermes (or anyone) signing its own root can't get a job run here."""
    from tenuo import Subpath, Warrant
    mine, hermes, grant, share = _setup(tmp_path, monkeypatch)
    forged = Warrant.mint_builder().capability("read_file", {"path": Subpath(str(share))}) \
        .holder(mine.public_key).ttl(60).mint(hermes)
    with pytest.raises(Exception):
        worker.check_job({"warrant": forged.to_base64(), "folder": "repo"}, key=mine, grant=grant,
                         revoked=set())


def test_hermes_cannot_widen_the_grant(tmp_path, monkeypatch):
    from tenuo import Exact, Pattern
    mine, hermes, grant, share = _setup(tmp_path, monkeypatch)
    for caps in ({"git_push": {"remote": Exact("origin"), "branch": Exact("main")}},
                 {"git_push": {"remote": Exact("upstream"), "branch": Exact("claude/x")}},
                 {"web_fetch": {"url": Pattern("*")}},
                 {"run_command": {"command": worker.command_constraint(["git push"])}}):
        with pytest.raises(Exception):
            _narrow(grant, hermes, mine.public_key, folder="repo", caps=caps)


def test_push_is_checked_per_branch(tmp_path, monkeypatch):
    from tenuo_claude_code import run
    mine, hermes, grant, share = _setup(tmp_path, monkeypatch)
    chain = run.decode_chain(_narrow(grant, hermes, mine.public_key, folder="repo",
                                     branch="claude/issue-78")["warrant"])
    assert worker.push_allowed(chain, mine, "origin", "claude/issue-78")[0]
    assert not worker.push_allowed(chain, mine, "origin", "main")[0]
    assert not worker.push_allowed(chain, mine, "origin", "claude/other")[0]


def test_grant_refuses_git_push_as_a_command(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="never a command"):
        _setup(tmp_path, monkeypatch, commands=["git push"])


def test_revoke_ends_the_grant(tmp_path, monkeypatch, capsys):
    mine, hermes, grant, share = _setup(tmp_path, monkeypatch)
    assert worker.load_grant("mac")["id"] == grant["id"]
    assert worker.main(["--name", "mac", "revoke"]) == 0
    assert worker.load_grant("mac") is None
    assert grant["id"] in worker.revoked_ids("mac")


def test_report_is_signed_and_fixed_shape(tmp_path, monkeypatch):
    from tenuo_claude_code import run
    mine, hermes, grant, _ = _setup(tmp_path, monkeypatch)
    summary = {"ok": True, "result": "I fixed it. Here is the key: SECRET", "allowed": 3,
               "denied": [{"tool": "Bash", "args": {"command": "cat ~/.ssh/id_ed25519"}}],
               "receipts": {"count": 4, "head": "abc", "chain_ok": True, "signed_by": "k"},
               "grant": {"grant_id": "g", "warrant_id": "w"}}
    short = worker.report_for(summary, mode="summary", branch="claude/x", pushed=True,
                              commits=[{"id": "a1b2c3d", "subject": "SECRET"}], push_error=None)
    assert "SECRET" not in __import__("json").dumps(short) and short["commits"] == ["a1b2c3d"]
    full = worker.report_for(summary, mode="full", branch="claude/x", pushed=True,
                             commits=[{"id": "a1b2c3d", "subject": "fix"}], push_error=None)
    assert full["result"].startswith("I fixed it") and full["denied"]
    chain = run.decode_chain(_narrow(grant, hermes, mine.public_key, folder="repo")["warrant"])
    signed = worker.sign_report(mine, short, chain)
    assert verify(signed) is True
    assert verify({**signed, "pushed": False}) is False


def verify(report):
    """What Hermes does with a report."""
    import tenuo_core
    from tenuo.meta import argument_json
    proof = report["proof"]
    body = {k: v for k, v in report.items() if k != "proof"}
    return tenuo_core.verify_meta(proof["warrant"], proof["signature"], worker.REPORT_TOOL,
                                  argument_json(body), proof["ts"])


FAKE_CLAUDE = """#!/bin/sh
# Stands in for claude -p: fixes the file and commits, as Claude would under the grant.
printf 'def add(a, b):\\n    return a + b\\n' > calc.py
git add calc.py && git -c user.name=t -c user.email=t@example.com commit -qm "Fix add"
echo '{"result": "fixed", "is_error": false}'
"""


def _git(cwd, *args):
    import subprocess
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


def test_handle_runs_on_a_branch_and_pushes_only_it(tmp_path, monkeypatch):
    mine, hermes, grant, share = _setup(tmp_path, monkeypatch)
    remote = tmp_path / "remote.git"
    _git(tmp_path, "init", "-q", "--bare", str(remote))
    repo = share / "repo"
    _git(repo, "init", "-q", "-b", "main")
    (repo / "calc.py").write_text("def add(a, b):\n    return a - b\n")
    _git(repo, "add", ".")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "init")
    _git(repo, "remote", "add", "origin", str(remote))
    _git(repo, "push", "-q", "origin", "main")
    claude = tmp_path / "claude"
    claude.write_text(FAKE_CLAUDE)
    claude.chmod(0o755)

    sent = {}

    class FakeHermes:
        key = mine
        def progress(self, job_id, line): sent.setdefault("progress", []).append(line)
        def result(self, job_id, report): sent["result"] = report

    job = _narrow(grant, hermes, mine.public_key, folder="repo", branch="claude/issue-78")
    report = worker.handle(FakeHermes(), job, name="mac", claude=str(claude))
    assert report["ok"] and report["pushed"] and report["branch"] == "claude/issue-78", report
    assert len(report["commits"]) == 1 and "result" not in report
    assert "claude/issue-78" in _git(remote, "branch")
    assert _git(remote, "log", "-1", "--format=%s", "main").strip() == "init"  # main untouched
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip() == "main"   # back where it was
    assert report["receipts"]["chain_ok"] and report["receipts"]["count"] >= 1


def test_handle_refuses_a_branch_outside_the_grant(tmp_path, monkeypatch):
    mine, hermes, grant, share = _setup(tmp_path, monkeypatch, push="claude/*")
    sent = {}

    class FakeHermes:
        key = mine
        def progress(self, *a): pass
        def result(self, job_id, report): sent["r"] = report

    job = _narrow(grant, hermes, mine.public_key, folder="repo", branch="claude/a")
    report = worker.handle(FakeHermes(), {**job, "branch": "main"}, name="mac", claude="/bin/false")
    assert not report["ok"] and "outside this machine's grant" in report["error"]


def test_machine_key_is_private_and_stable(tmp_path, monkeypatch):
    monkeypatch.setattr(worker, "KEY_DIR", tmp_path / "keys")
    a = worker.machine_key("laptop")
    b = worker.machine_key("laptop")
    assert a.public_key.to_bytes() == b.public_key.to_bytes()
    assert (tmp_path / "keys" / "laptop.key").stat().st_mode & 0o077 == 0


def test_progress_line():
    assert worker.progress_line({"tool": "Bash", "decision": "deny", "args": {"command": "git push"}}) \
        == "⛔ Bash git push"
    assert worker.progress_line({"tool": "Edit", "decision": "allow", "args": {"path": "/a/b/calc.py"}}) \
        == "✅ Edit calc.py"
    assert worker.progress_line({"tool": "TodoWrite", "decision": "allow"}) is None


def test_a_job_without_commits_leaves_no_branch(tmp_path, monkeypatch):
    mine, hermes, grant, share = _setup(tmp_path, monkeypatch)
    repo = share / "repo"
    _git(tmp_path, "init", "-q", "--bare", str(tmp_path / "remote.git"))
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a").write_text("a")
    _git(repo, "add", ".")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "init")
    _git(repo, "remote", "add", "origin", str(tmp_path / "remote.git"))
    claude = tmp_path / "claude"
    claude.write_text("#!/bin/sh\necho '{\"result\": \"nothing to do\"}'\n")
    claude.chmod(0o755)

    class FakeHermes:
        key = mine
        def progress(self, *a): pass
        def result(self, *a): pass

    job = _narrow(grant, hermes, mine.public_key, folder="repo", branch="claude/x")
    report = worker.handle(FakeHermes(), job, name="mac", claude=str(claude))
    assert report["ok"] and not report["pushed"]
    assert "claude/x" not in _git(repo, "branch")
    # The same name works again, and an existing branch is refused clearly.
    _git(repo, "branch", "claude/x")
    report = worker.handle(FakeHermes(), job, name="mac", claude=str(claude))
    assert not report["ok"] and "already has a branch" in report["error"]
