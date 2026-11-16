"""`tenuo-claude worker`: Claude Code on this machine, for jobs a Hermes agent sends."""

import base64

import pytest

from tenuo_claude_code import worker


def _b64(raw):
    return base64.b64encode(bytes(raw)).decode()


def _job(issuer, holder_pub, folder="repo", ttl=300):
    from tenuo import Subpath, Warrant
    w = Warrant.mint_builder().capability("read_file", {"path": Subpath("/x")}) \
        .holder(holder_pub).ttl(ttl).mint(issuer)
    return {"id": "j1", "warrant": w.to_base64(), "folder": folder, "minutes": 5,
            "issuer": _b64(issuer.public_key.to_bytes())}


def test_folder_must_be_inside_the_share(tmp_path):
    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "link").symlink_to("/etc")
    assert worker.folder_in_share(tmp_path, "repo") == (tmp_path / "repo").resolve()
    for bad in ("../x", "/etc", "", "repo/link", "missing"):
        with pytest.raises(ValueError):
            worker.folder_in_share(tmp_path, bad)


def test_check_job(tmp_path):
    from tenuo import SigningKey
    (tmp_path / "repo").mkdir()
    issuer, mine = SigningKey.generate(), SigningKey.generate()
    root = _b64(issuer.public_key.to_bytes())
    assert worker.check_job(_job(issuer, mine.public_key), key=mine, share=tmp_path, trusted_root=root)
    with pytest.raises(ValueError, match="held by this machine"):
        worker.check_job(_job(issuer, SigningKey.generate().public_key), key=mine, share=tmp_path,
                         trusted_root=root)
    with pytest.raises(ValueError, match="doesn't trust"):
        other = SigningKey.generate()
        worker.check_job(_job(other, mine.public_key), key=mine, share=tmp_path, trusted_root=root)
    with pytest.raises(ValueError, match="outside|relative"):
        worker.check_job(_job(issuer, mine.public_key, folder="../.."), key=mine, share=tmp_path,
                         trusted_root=root)


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
