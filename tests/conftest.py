"""Shared fixtures for the tenuo-claude-code unit tests.

These tests exercise the PURE decision logic — routing, constraint construction,
approval encoding, subagent attenuation routing — with no Docker, no authorizer,
and no network. The point is a fast feedback loop and a CI gate that proves the
leash's *logic* (not just that `init` writes files). Anything that needs a live
authorizer lives in the `verify` self-test / the enforcement CI job instead.
"""
from __future__ import annotations

import pytest

from tenuo_claude_code import cli


@pytest.fixture
def cli_mod():
    """The module under test."""
    return cli


@pytest.fixture
def make_cfg():
    """Factory for a minimal in-memory policy dict (what load_config produces,
    minus the file I/O). Override any key via kwargs."""
    def _make(**over):
        cfg = {
            "_sandbox_abs": "/sandbox",
            "enforce": {},
            "mcp": {},
            "audit": [],
            "default": "deny",
            "mode": "enforce",
            "_managed": False,
        }
        cfg.update(over)
        return cfg
    return _make


@pytest.fixture
def bound(monkeypatch, tmp_path):
    """Bind cli's project-scoped path globals to a temp project.

    cli declares these as bare annotations (set at runtime by
    paths.bind_project_paths); for unit tests we point them at a tmp dir so the
    state-touching helpers (subwarrant_path, ensure_state_dir, write_secret,
    agent_definitions) operate in isolation.
    """
    state = tmp_path / ".state"
    agents = tmp_path / ".claude" / "agents"
    binding = {
        "DEMO_DIR": tmp_path,
        "STATE": state,
        "STATE_JSON": state / "state.json",
        "GATEWAY": state / "gateway.yaml",
        "SRL": state / "srl.cbor",
        "AGENTS_DIRS": (agents, tmp_path / "no-such-user-agents"),
        "HOLDER_KEY": state / "holder_key.b64",
        "ISSUER_KEY": state / "issuer_key.b64",
        "ISSUER_PUB": state / "issuer_pub.hex",
        "RECEIPT_KEY": state / "receipt_key.b64",
        "RECEIPT_PUB": state / "receipt_pub.hex",
        "RECEIPTS": state / "receipts.jsonl",
        "WARRANT": state / "warrant.b64",
        "CLOUD_ENV": state / "cloud.env",
    }
    for name, value in binding.items():
        monkeypatch.setattr(cli, name, value, raising=False)
    return tmp_path


@pytest.fixture(autouse=True)
def _isolated_home(monkeypatch, tmp_path_factory):
    """Per-project state resolves under ~/.tenuo; keep tests out of the real home."""
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("TENUO_STATE_DIR", raising=False)
