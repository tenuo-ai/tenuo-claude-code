"""What happens when a session warrant expires.

A one-hour warrant that only `tenuo-claude up` could renew left a day-old
setup denying every call, and made `audit --verify` reject every receipt
older than an hour. Local warrants now renew themselves with the same
permissions (never from tenuo.yaml, so a policy edit still needs `refresh`),
and a receipt is judged as of the moment it records.
"""
from __future__ import annotations

import base64
import json
import time

import pytest
from tenuo import SigningKey, Warrant
from tenuo_core import decode_warrant_stack_base64

from tenuo_claude_code import cli


@pytest.fixture
def local(bound, make_cfg, monkeypatch):
    """A local-mode project with real keys and a freshly minted session warrant."""
    monkeypatch.setattr(cli, "use_cloud_trigger", lambda cfg: False)
    cfg = make_cfg(enforce={"Read": "subpath:{sandbox}", "Bash": "shlex:ls,pwd"},
                   _sandbox_abs=str(bound))
    cli.ensure_state_dir()
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    cli.write_secret(cli.ISSUER_KEY, base64.b64encode(bytes(issuer.secret_key_bytes())).decode())
    cli.write_secret(cli.HOLDER_KEY, base64.b64encode(bytes(holder.secret_key_bytes())).decode())
    cli.write_secret(cli.WARRANT, cli.mint_local_warrant(cfg, issuer, holder).to_base64())
    return cfg


def due(monkeypatch):
    """Treat the current warrant as past its deadline, without waiting."""
    monkeypatch.setattr(cli, "_warrant_seconds_left", lambda warrant: -1.0)


def current() -> Warrant:
    return Warrant.from_base64(cli.WARRANT.read_text())


def receipts() -> list[dict]:
    if not cli.RECEIPTS.exists():
        return []
    return [json.loads(line)["payload"] for line in cli.RECEIPTS.read_text().splitlines()]


def test_fresh_warrant_is_left_alone(local):
    before = cli.WARRANT.read_text()
    assert cli.renew_session_warrant_if_due(local) is None
    assert cli.WARRANT.read_text() == before
    assert receipts() == []


def test_due_warrant_is_reminted_with_the_same_permissions(local, monkeypatch):
    old = current()
    due(monkeypatch)
    new_id = cli.renew_session_warrant_if_due(local)
    new = current()
    assert new_id == new.id != old.id
    assert not new.is_expired()
    assert cli._capability_signature(new) == cli._capability_signature(old)
    assert json.loads(cli.STATE_JSON.read_text())["warrant_id"] == new.id
    (row,) = receipts()
    assert row["phase"] == "renew"
    assert (row["old_warrant_id"], row["new_warrant_id"]) == (old.id, new.id)
    assert oct(cli.WARRANT.stat().st_mode & 0o777) == "0o600"


def test_a_really_expired_warrant_is_renewed(local, make_cfg, bound):
    cfg = {**local, "ttl_seconds": 1}
    issuer = SigningKey.from_bytes(base64.b64decode(cli.ISSUER_KEY.read_text()))
    holder = SigningKey.from_bytes(base64.b64decode(cli.HOLDER_KEY.read_text()))
    cli.write_secret(cli.WARRANT, cli.mint_local_warrant(cfg, issuer, holder).to_base64())
    time.sleep(2.1)
    assert current().is_expired()
    assert cli.renew_session_warrant_if_due({**local, "ttl_seconds": 600}) is not None
    assert not current().is_expired()


def test_renewal_ignores_an_edited_policy(local, make_cfg, bound, monkeypatch):
    """Widening tenuo.yaml must not widen the renewed warrant."""
    old = current()
    widened = make_cfg(enforce={"Read": "subpath:/", "Bash": "shlex:ls,pwd,rm,curl",
                                "Write": "subpath:/"}, _sandbox_abs="/")
    due(monkeypatch)
    assert cli.renew_session_warrant_if_due(widened) is not None
    new = current()
    assert cli._capability_signature(new) == cli._capability_signature(old)
    assert sorted(new.tools) == sorted(old.tools)


def test_auto_renew_false_keeps_the_warrant_expired(local, monkeypatch):
    before = cli.WARRANT.read_text()
    due(monkeypatch)
    assert cli.renew_session_warrant_if_due({**local, "auto_renew": False}) is None
    assert cli.WARRANT.read_text() == before


@pytest.mark.parametrize("kind", ["cloud-trigger", "managed"])
def test_cloud_and_managed_warrants_are_never_renewed_locally(local, monkeypatch, kind):
    before = cli.WARRANT.read_text()
    due(monkeypatch)
    cfg = dict(local)
    if kind == "cloud-trigger":
        monkeypatch.setattr(cli, "use_cloud_trigger", lambda cfg: True)
    else:
        cfg["_managed"] = True
    assert cli.renew_session_warrant_if_due(cfg) is None
    assert cli.WARRANT.read_text() == before


def test_a_warrant_from_another_issuer_is_not_replaced(local, monkeypatch):
    """A Cloud-issued warrant left in a project must not become a local one."""
    holder = SigningKey.from_bytes(base64.b64decode(cli.HOLDER_KEY.read_text()))
    foreign = cli.mint_local_warrant(local, SigningKey.generate(), holder).to_base64()
    cli.write_secret(cli.WARRANT, foreign)
    due(monkeypatch)
    assert cli.renew_session_warrant_if_due(local) is None
    assert cli.WARRANT.read_text() == foreign


def test_subagent_warrants_follow_the_new_session_warrant(local, monkeypatch):
    cfg = {**local, "subagents": {"researcher": {"tools": ["Read"]}}}
    cli.refresh_subwarrants(cfg)
    path = cli.subwarrant_path("researcher")
    old_child = decode_warrant_stack_base64(path.read_text())[-1]
    due(monkeypatch)
    # The role's tool list was widened in the policy after the warrant was applied.
    edited = {**cfg, "subagents": {"researcher": {"tools": ["Read", "Bash"]}}}
    assert cli.renew_session_warrant_if_due(edited) is not None
    parent, child = decode_warrant_stack_base64(path.read_text())
    assert parent.id == current().id
    assert sorted(child.tools) == sorted(old_child.tools) == ["read_file"]
    assert not child.is_expired()


def test_missing_keys_or_garbage_never_raise(local, monkeypatch):
    due(monkeypatch)
    cli.WARRANT.write_text("not-a-warrant")
    assert cli.renew_session_warrant_if_due(local) is None
    cli.ISSUER_KEY.unlink()
    assert cli.renew_session_warrant_if_due(local) is None


def test_every_authorization_checks_for_a_due_warrant(local, monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "renew_session_warrant_if_due", lambda cfg: seen.append(cfg))
    cli.authorize_call(local, "Read", {"file_path": str(cli.DEMO_DIR / "tenuo.yaml")}, None, {})
    assert seen == [local]


def test_expiry_note_for_status_and_check(local, monkeypatch):
    # A healthy warrant that renews itself is not a warning.
    assert cli.warrant_expiry_note(local) == ("ok", "renews automatically")
    manual = {**local, "auto_renew": False}
    # A fresh one-hour warrant is not "expiring soon" the moment it is minted.
    assert cli.warrant_expiry_note(manual) == ("ok", "")
    monkeypatch.setattr(cli, "_warrant_seconds_left", lambda warrant: 600.0)
    state, note = cli.warrant_expiry_note(manual)
    assert state == "soon" and note.startswith("expires soon")


def test_expiry_note_when_expired(local, monkeypatch):
    class Expired:
        def is_expired(self):
            return True

    import tenuo
    monkeypatch.setattr(tenuo.Warrant, "from_base64", staticmethod(lambda raw: Expired()),
                        raising=False)
    assert cli.warrant_expiry_note(local) == ("ok", "expired; renews on the next tool call")
    assert cli.warrant_expiry_note({**local, "auto_renew": False}) == ("expired", "")


def test_audit_prints_a_renewal_line(local, monkeypatch, capsys):
    due(monkeypatch)
    cli.renew_session_warrant_if_due(local)
    import argparse
    monkeypatch.setattr(cli, "load_config", lambda: local)
    cli.cmd_audit(argparse.Namespace(verify=False, json=False, tail=None, limit=None))
    assert "renewed  warrant tnu_wrt_" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Audit: a receipt is judged as of the moment it records
# ---------------------------------------------------------------------------


def root_hex() -> str:
    issuer = SigningKey.from_bytes(base64.b64decode(cli.ISSUER_KEY.read_text()))
    return bytes(issuer.public_key.to_bytes()).hex()


def mint_short_lived(cfg) -> tuple[Warrant, float]:
    issuer = SigningKey.from_bytes(base64.b64decode(cli.ISSUER_KEY.read_text()))
    holder = SigningKey.from_bytes(base64.b64decode(cli.HOLDER_KEY.read_text()))
    minted_at = time.time()
    warrant = cli.mint_local_warrant({**cfg, "ttl_seconds": 1}, issuer, holder)
    cli.write_secret(cli.WARRANT, warrant.to_base64())
    cli.ISSUER_PUB.write_text(root_hex())
    return warrant, minted_at


def evidence(cfg, warrant: Warrant, when: float) -> dict:
    import hashlib
    tool, _route, sign_args, _body, _governed = cli.resolve_tool(
        cfg, "Read", {"file_path": str(cli.DEMO_DIR / "a.py")})
    stack = warrant.to_base64()
    return {"warrant_stack_b64": stack,
            "warrant_stack_hash": hashlib.sha256(cli._decode_b64url_or_standard(stack)).hexdigest(),
            "warrant_id": warrant.id, "tenuo_tool": tool, "sign_args": sign_args,
            "pop_b64": "unused-by-replay", "pop_ts": int(when)}


def test_receipts_under_a_since_expired_warrant_still_verify(local):
    warrant, minted_at = mint_short_lived(local)
    time.sleep(2.1)
    assert warrant.is_expired()
    # An allow made while the warrant was valid holds.
    made_in_time = {"decision": "allow", "authz": evidence(local, warrant, minted_at)}
    assert cli._verify_authz_evidence(made_in_time, 1) == []
    # An allow dated after expiry does not.
    too_late = {"decision": "allow", "authz": evidence(local, warrant, time.time())}
    (error,) = cli._verify_authz_evidence(too_late, 2)
    assert "already expired" in error
    # A deny dated after expiry is what the authorizer would have said.
    denied = {"decision": "deny", "authz": evidence(local, warrant, time.time())}
    assert cli._verify_authz_evidence(denied, 3) == []


def test_expired_chain_checks_root_signature_link_and_scope(local):
    cfg = {**local, "subagents": {"researcher": {"tools": ["Read"]}}}
    parent, minted_at = mint_short_lived(cfg)
    cli.refresh_subwarrants(cfg)
    chain = decode_warrant_stack_base64(cli.subwarrant_path("researcher").read_text())
    time.sleep(2.1)
    roots = [root_hex()]
    assert cli._verify_chain_as_of(chain, roots, minted_at, "allow") is None

    stranger = bytes(SigningKey.generate().public_key.to_bytes()).hex()
    assert "trusted root" in cli._verify_chain_as_of(chain, [stranger], minted_at, "allow")
    assert "timestamp" in cli._verify_chain_as_of(chain, roots, None, "allow")

    # A child that belongs to a different session warrant does not link.
    other_parent, _ = mint_short_lived(cfg)
    assert "link" in cli._verify_chain_as_of([other_parent, chain[1]], roots, minted_at, "allow")

    # A child holding a tool its parent lacks is refused.
    issuer = SigningKey.from_bytes(base64.b64decode(cli.ISSUER_KEY.read_text()))
    holder = SigningKey.from_bytes(base64.b64decode(cli.HOLDER_KEY.read_text()))
    narrow_parent = (Warrant.mint_builder().capability("grep", {})
                     .holder(holder.public_key).ttl(60).mint(issuer))

    class Lying:
        """A correctly signed and linked child that reports a wider tool set."""
        def __init__(self, real, caps):
            self._real, self.capabilities = real, caps
        def __getattr__(self, name):
            return getattr(self._real, name)

    builder = narrow_parent.attenuate_builder()
    builder.inherit_all()
    real_child = builder.delegate(holder)
    wide = Lying(real_child, {"grep": {}, "run_command": {}})
    assert "beyond its parent" in cli._verify_chain_as_of(
        [narrow_parent, wide], roots, time.time(), "allow")
