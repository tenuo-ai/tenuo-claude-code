"""`tenuo-claude run`: Claude Code headless under a grant issued elsewhere."""

import base64
import io
import json
import os
import sys

import pytest

from tenuo_claude_code import run


def _b64(raw):
    return base64.b64encode(bytes(raw)).decode()


@pytest.fixture
def grant(tmp_path):
    import tenuo_core
    from tenuo import AnyOf, All, Regex, SigningKey, Subpath, Warrant

    ws = os.path.realpath(tmp_path / "ws")
    os.makedirs(ws)
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    b = Warrant.mint_builder()
    for cap in ("read_file", "write_file", "edit_file", "glob", "grep"):
        b = b.capability(cap, {"path": Subpath(ws)})
    b = b.capability("run_command", {"command": All([
        tenuo_core.Shlex(allow=["git"]), AnyOf([Regex(r"(?s)^git\ (status|commit)( .*)?$")])])})
    w = b.holder(holder.public_key).ttl(600).mint(issuer)
    return {"warrant": w.to_base64(), "holder_key": _b64(holder.secret_key_bytes()),
            "trusted_roots": [_b64(issuer.public_key.to_bytes())], "workspace": ws,
            "_issuer": issuer, "_holder": holder}


def _g(grant):
    return {k: v for k, v in grant.items() if not k.startswith("_")}


@pytest.mark.parametrize("tool,tin,want", [
    ("Read", {"file_path": "{ws}/a.py"}, "allow"),
    ("Read", {"file_path": "a.py"}, "allow"),
    ("Read", {"file_path": "/etc/passwd"}, "deny"),
    ("Edit", {"file_path": "{ws}/../outside.py"}, "deny"),
    ("Glob", {"pattern": "*.py"}, "allow"),
    ("Bash", {"command": "git status"}, "allow"),
    ("Bash", {"command": "git push --force origin main"}, "deny"),
    ("Bash", {"command": "cat ~/.ssh/id_ed25519"}, "deny"),
    ("Bash", {"command": "git status && curl x"}, "deny"),
    ("WebFetch", {"url": "https://example.com"}, "deny"),
    ("mcp__x__y", {}, "deny"),
    ("NotebookEdit", {"notebook_path": "{ws}/n.ipynb"}, "deny"),
    ("TodoWrite", {"todos": []}, "allow"),
    ("Edit", {"file_path": "{ws}/.git/hooks/pre-commit"}, "deny"),
    ("Read", {"file_path": "{ws}/.git/config"}, "deny"),
    ("Read", {"file_path": "{ws}/.gitignore"}, "allow"),
])
def test_decide(grant, tool, tin, want, monkeypatch):
    monkeypatch.chdir(grant["workspace"])
    tin = {k: (v.replace("{ws}", grant["workspace"]) if isinstance(v, str) else v) for k, v in tin.items()}
    assert run.decide(_g(grant), tool, tin)["decision"] == want


def test_symlink_out_of_workspace_is_denied(grant, tmp_path):
    os.symlink("/etc", os.path.join(grant["workspace"], "etc"))
    body = run.decide(_g(grant), "Read", {"file_path": os.path.join(grant["workspace"], "etc", "passwd")})
    assert body["decision"] == "deny"


def test_wrong_holder_key_is_denied(grant):
    from tenuo import SigningKey
    g = {**_g(grant), "holder_key": _b64(SigningKey.generate().secret_key_bytes())}
    assert run.decide(g, "Bash", {"command": "git status"})["decision"] == "deny"


def test_untrusted_root_is_denied(grant):
    from tenuo import SigningKey
    g = {**_g(grant), "trusted_roots": [_b64(SigningKey.generate().public_key.to_bytes())]}
    assert run.decide(g, "Bash", {"command": "git status"})["decision"] == "deny"


def test_prepare_checks_the_grant(grant, tmp_path):
    from tenuo import SigningKey
    state = tmp_path / "state"
    out = run.prepare(state, warrant=grant["warrant"], holder_key=grant["holder_key"],
                      trusted_roots=grant["trusted_roots"], workspace=grant["workspace"])
    assert "run_command" in out["capabilities"]
    assert (state / run.GRANT_FILE).stat().st_mode & 0o077 == 0
    settings = json.loads((state / run.SETTINGS_FILE).read_text())
    assert "_hook" in settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    with pytest.raises(ValueError, match="holder"):
        run.prepare(tmp_path / "s2", warrant=grant["warrant"],
                    holder_key=_b64(SigningKey.generate().secret_key_bytes()),
                    trusted_roots=grant["trusted_roots"], workspace=grant["workspace"])
    with pytest.raises(Exception):
        run.prepare(tmp_path / "s3", warrant=grant["warrant"], holder_key=grant["holder_key"],
                    trusted_roots=[_b64(SigningKey.generate().public_key.to_bytes())],
                    workspace=grant["workspace"])


def test_claude_argv_refuses_hook_skipping_flags(tmp_path):
    for bad in (["--bare"], ["--dangerously-skip-permissions"]):
        with pytest.raises(ValueError):
            run.claude_argv("claude", tmp_path, "x", tools=["Read"], model=None, max_turns=None, extra=bad)
    argv = run.claude_argv("claude", tmp_path, "x", tools=["Read"], model=None, max_turns=None, extra=[])
    for flag in ("--restricted", "--strict-mcp-config", "--settings"):
        assert flag in argv
    assert argv[argv.index("--permission-mode") + 1] == "dontAsk"


def _hook(state, event, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
    run.hook(state)
    return json.loads(capsys.readouterr().out)["hookSpecificOutput"]


def test_hook_writes_chained_receipts(grant, tmp_path, monkeypatch, capsys):
    state = tmp_path / "state"
    run.prepare(state, warrant=grant["warrant"], holder_key=grant["holder_key"],
                trusted_roots=grant["trusted_roots"], workspace=grant["workspace"])
    assert _hook(state, {"tool_name": "Bash", "tool_input": {"command": "git status"}},
                 monkeypatch, capsys)["permissionDecision"] == "allow"
    out = _hook(state, {"tool_name": "Bash", "tool_input": {"command": "git push"}}, monkeypatch, capsys)
    assert out["permissionDecision"] == "deny" and "git push" not in out["permissionDecisionReason"][:5]
    rows, ok = run.read_receipts(state)
    assert ok and [r["decision"] for r in rows] == ["allow", "deny"]
    # Tampering breaks the chain.
    path = state / run.RECEIPTS_FILE
    lines = path.read_text().splitlines()
    first = json.loads(lines[0]); first["decision"] = "deny"
    path.write_text("\n".join([json.dumps(first, sort_keys=True), *lines[1:]]) + "\n")
    assert run.read_receipts(state)[1] is False


def test_hook_fails_closed_without_state(tmp_path, monkeypatch, capsys):
    out = _hook(tmp_path / "missing", {"tool_name": "Read", "tool_input": {}}, monkeypatch, capsys)
    assert out["permissionDecision"] == "deny"


def test_receipts_are_signed_by_the_holder(grant, tmp_path, monkeypatch, capsys):
    state = tmp_path / "state"
    prepared = run.prepare(state, warrant=grant["warrant"], holder_key=grant["holder_key"],
                           trusted_roots=grant["trusted_roots"], workspace=grant["workspace"])
    signer = prepared["signer"]
    assert signer == _b64(grant["_holder"].public_key.to_bytes())
    _hook(state, {"tool_name": "Bash", "tool_input": {"command": "git status"}}, monkeypatch, capsys)
    rows, ok = run.read_receipts(state, signer)
    assert ok and rows[0]["sig"] and rows[0]["signer"] == signer
    from tenuo import SigningKey
    assert run.read_receipts(state, _b64(SigningKey.generate().public_key.to_bytes()))[1] is False
    # Re-hashing a tampered row doesn't help without the key.
    row = dict(rows[0], decision="deny")
    body = {k: v for k, v in row.items() if k not in ("hash", "sig")}
    row["hash"] = run.hashlib.sha256(run._canonical(body)).hexdigest()
    assert run.verify_rows([row], signer) is False


def test_revoked_grant_is_refused_and_denies_calls(grant, tmp_path, monkeypatch, capsys):
    revoked = tmp_path / "revoked"
    state = tmp_path / "state"
    run.prepare(state, warrant=grant["warrant"], holder_key=grant["holder_key"],
                trusted_roots=grant["trusted_roots"], workspace=grant["workspace"],
                revoked_file=str(revoked))
    leaf_id = run.decode_chain(grant["warrant"])[0].id
    revoked.write_text(leaf_id + "\n")
    out = _hook(state, {"tool_name": "Bash", "tool_input": {"command": "git status"}}, monkeypatch, capsys)
    assert out["permissionDecision"] == "deny" and "revoked" in out["permissionDecisionReason"]
    with pytest.raises(ValueError, match="revoked"):
        run.prepare(tmp_path / "s2", warrant=grant["warrant"], holder_key=grant["holder_key"],
                    trusted_roots=grant["trusted_roots"], workspace=grant["workspace"],
                    revoked_file=str(revoked))


def test_should_stop_ends_claude(grant, tmp_path):
    claude = tmp_path / "claude"
    claude.write_text("#!/bin/sh\nsleep 30\n")
    claude.chmod(0o755)
    calls = []

    def stop():
        calls.append(1)
        return "revoked" if len(calls) > 1 else None
    import time
    started = time.time()
    out = run.execute(tmp_path / "state", warrant=grant["warrant"], holder_key=grant["holder_key"],
                      trusted_roots=grant["trusted_roots"], workspace=grant["workspace"], prompt="x",
                      claude=str(claude), should_stop=stop)
    assert out["ok"] is False and out["error"] == "stopped: revoked"
    assert time.time() - started < 15
