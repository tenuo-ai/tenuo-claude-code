"""`tenuo-claude accept` and `shared`: using an MCP server someone shared with you.

No network: the owner's server is a fake answering the two pairing routes.
"""
from __future__ import annotations

import argparse
import base64
import stat

import pytest
from tenuo import SigningKey, Warrant, Wildcard

from tenuo_claude_code import shared

LINK = "http://owner.example:8765/#HG-AAAA-BBBB"


class FakeOwner:
    """The owner's side of pairing: an invitation, an approval, an ending."""

    def __init__(self):
        self.issuer = SigningKey.generate()
        self.holder = None
        self.status = "pending"
        self.code_used = False
        self.approve_on_pair = False

    def approve(self, tools=("list_events",)):
        builder = Warrant.mint_builder().holder(_public(self.holder)).ttl(3600)
        for tool in tools:
            builder = builder.capability(tool, day=Wildcard())
        self.warrant = builder.mint(self.issuer)
        self.status = "approved"

    def __call__(self, method, url, **kw):
        if url.endswith("/tenuo/pair"):
            if self.code_used:
                return _Response(404, {"error": "This invitation isn't valid. Ask for a new one."})
            self.code_used = True
            self.holder = kw["json"]["public_key"]
            if self.approve_on_pair:
                self.approve()
            return _Response(202, {"status": "pending"})
        body = {"status": self.status}
        if self.status == "approved":
            body.update(warrant=self.warrant.to_base64(), name="Calendar",
                        issuer=base64.b64encode(bytes(self.issuer.public_key_bytes())).decode())
        return _Response(200 if self.status == "approved" else 202, body)


class _Response:
    def __init__(self, status_code, body):
        self.status_code, self._body = status_code, body

    def json(self):
        return self._body


def _public(holder_b64):
    from tenuo import PublicKey

    return PublicKey.from_bytes(base64.b64decode(holder_b64))


def _args(**over):
    base = {"link": LINK, "person": "Alex", "agent": "Claude Code", "scope": "user", "wait": 0,
            "yes": False, "no_claude": True}
    base.update(over)
    return argparse.Namespace(**base)


@pytest.fixture
def owner(tmp_path, monkeypatch):
    fake = FakeOwner()
    monkeypatch.setattr(shared, "STORE", tmp_path / "shared")
    monkeypatch.setattr(shared, "_http", fake)
    monkeypatch.setattr(shared.time, "sleep", lambda _s: None)
    return fake


def test_link_must_be_whole():
    with pytest.raises(shared.SharedError, match="whole invitation link"):
        shared.parse_link("http://owner.example:8765/")
    with pytest.raises(shared.SharedError):
        shared.parse_link("HG-AAAA-BBBB")
    assert shared.parse_link(f"'{LINK}'") == ("http://owner.example:8765", "HG-AAAA-BBBB")


def test_accept_pins_the_owner_key_and_keeps_the_key_private(owner, capsys):
    owner.approve_on_pair = True
    assert shared.cmd_accept(_args()) == 0
    out = capsys.readouterr().out
    assert "Approved: list_events until" in out
    assert "claude mcp add --scope user calendar --" in out
    state = shared.load("calendar")
    assert state["issuer"] == base64.b64encode(bytes(owner.issuer.public_key_bytes())).decode()
    folder = shared.STORE / "calendar"
    for path in (shared.STORE, folder, folder / "key", folder / "server.json"):
        assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0, path


def test_waiting_resumes_without_reusing_the_code(owner, capsys):
    assert shared.cmd_accept(_args()) == 1
    assert "Still waiting" in capsys.readouterr().out
    owner.approve()
    assert shared.cmd_accept(_args()) == 0  # same command again: no second pairing
    assert "Approved" in capsys.readouterr().out


def test_declined_and_reused_codes_say_so(owner, capsys):
    owner.status = "declined"
    assert shared.cmd_accept(_args()) == 2
    assert "declined" in capsys.readouterr().out
    shared.STORE.joinpath(".pending").rename(shared.STORE / "old")
    assert shared.cmd_accept(_args()) == 2
    assert "isn't valid" in capsys.readouterr().out


def test_accept_changes_nothing_else(owner, tmp_path, monkeypatch):
    """Installing and accepting must not touch Claude settings, hooks or the project."""
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir(), project.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(project)
    owner.status = "pending"
    shared.cmd_accept(_args())
    assert list(home.iterdir()) == [] and list(project.iterdir()) == []


def test_claude_command_names_server_before_env(monkeypatch):
    monkeypatch.setenv("TENUO_SHARED_HOME", "/tmp/x")
    command = shared.claude_add_command("calendar", "project")
    assert command[:6] == ["claude", "mcp", "add", "--scope", "project", "calendar"]
    assert command[6:8] == ["-e", f"TENUO_SHARED_HOME={shared.STORE}"]
    assert command[command.index("--") + 1:][-3:] == ["shared", "run", "calendar"]


def test_names_are_unique_and_safe(owner, tmp_path):
    (shared.STORE / "calendar").mkdir(parents=True)
    (shared.STORE / "calendar" / "server.json").write_text("{}")
    assert shared.suggest_name("http://h:1", "Calendar") == "calendar-2"
    assert shared.suggest_name("http://my.host:1", None) == "my-host"


def test_list_and_remove(owner, capsys):
    owner.approve_on_pair = True
    shared.cmd_accept(_args(wait=1))
    capsys.readouterr()
    assert shared.cmd_shared(argparse.Namespace(shared_cmd="list")) == 0
    assert "calendar" in capsys.readouterr().out
    owner.status = "ended"
    shared.cmd_shared(argparse.Namespace(shared_cmd="list"))
    assert "ended" in capsys.readouterr().out
    assert shared.cmd_shared(argparse.Namespace(shared_cmd="remove", name="calendar")) == 0
    assert not (shared.STORE / "calendar").exists()
    assert shared.cmd_shared(argparse.Namespace(shared_cmd="remove", name="calendar")) == 2
