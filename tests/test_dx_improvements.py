"""Unit coverage for the DX-clarity changes.

Pure logic only (no Docker / authorizer / network), in the spirit of conftest:
constraint error messages, the Cloud-drift policy fingerprint, the Bash denial
hint, and the receipt-sink failure signalling. See ROADMAP.md §8.
"""
from __future__ import annotations

import base64
import json
import time

import pytest

from tenuo_claude_code import cli


# --- #13: unknown constraint kind lists the valid kinds -----------------------

def test_unknown_constraint_kind_lists_valid_kinds(cli_mod):
    with pytest.raises(SystemExit) as exc:
        cli_mod.make_constraint("nope:bar", "/sb")
    msg = str(exc.value)
    assert "nope" in msg
    # Every supported kind is named so the author doesn't have to grep the docs.
    for kind in ("subpath", "shlex", "regex", "pattern", "oneof", "exact"):
        assert kind in msg


# --- #14: policy fingerprint detects capability drift, ignores local knobs ----

def test_fingerprint_stable_for_identical_policy(cli_mod, make_cfg):
    a = make_cfg(enforce={"Read": "subpath:{sandbox}", "Bash": "shlex:ls,pwd"})
    b = make_cfg(enforce={"Read": "subpath:{sandbox}", "Bash": "shlex:ls,pwd"})
    assert cli_mod.policy_capability_fingerprint(a) == cli_mod.policy_capability_fingerprint(b)


def test_fingerprint_changes_when_capabilities_change(cli_mod, make_cfg):
    base = make_cfg(enforce={"Bash": "shlex:ls,pwd"})
    widened = make_cfg(enforce={"Bash": "shlex:ls,pwd,cat"})  # added a verb
    assert cli_mod.policy_capability_fingerprint(base) != cli_mod.policy_capability_fingerprint(widened)


def test_fingerprint_changes_when_audit_capabilities_change(cli_mod, make_cfg):
    base = make_cfg(audit=["WebSearch"])
    widened = make_cfg(audit=["WebSearch", "TodoWrite"])
    assert cli_mod.policy_capability_fingerprint(base) != cli_mod.policy_capability_fingerprint(widened)


def test_fingerprint_tracks_subagents_and_default(cli_mod, make_cfg):
    base = make_cfg(enforce={"Read": "subpath:{sandbox}"})
    with_role = make_cfg(enforce={"Read": "subpath:{sandbox}"},
                         subagents={"researcher": {"tools": ["Read", "Grep"]}})
    assert cli_mod.policy_capability_fingerprint(base) != cli_mod.policy_capability_fingerprint(with_role)
    assert (cli_mod.policy_capability_fingerprint(make_cfg(default="deny"))
            != cli_mod.policy_capability_fingerprint(make_cfg(default="approve")))


def test_fingerprint_ignores_mode(cli_mod, make_cfg):
    # `mode` is a local runtime posture, NOT baked into the Cloud trigger — it must
    # not register as drift (otherwise flipping enforce<->audit would nag for setup).
    enforce = make_cfg(enforce={"Read": "subpath:{sandbox}"}, mode="enforce")
    audit = make_cfg(enforce={"Read": "subpath:{sandbox}"}, mode="audit")
    assert cli_mod.policy_capability_fingerprint(enforce) == cli_mod.policy_capability_fingerprint(audit)


# --- #15: Bash denials explain the shlex verb-vs-path distinction --------------

def test_bash_denial_reason_augmented(cli_mod, make_cfg):
    cfg = make_cfg(enforce={"Bash": "shlex:ls,pwd"})
    out = cli_mod._augment_denial_reason(cfg, "Bash", "constraint failed")
    assert "constraint failed" in out
    assert "verb" in out.lower() and "path" in out.lower()


def test_non_bash_denial_reason_unchanged(cli_mod, make_cfg):
    cfg = make_cfg(enforce={"Read": "subpath:{sandbox}", "Bash": "shlex:ls"})
    assert cli_mod._augment_denial_reason(cfg, "Read", "nope") == "nope"


def test_bash_without_shlex_not_augmented(cli_mod, make_cfg):
    # If Bash isn't governed by a shlex allowlist, the verb/path note doesn't apply.
    cfg = make_cfg(enforce={"Bash": "regex:^ls$"})
    assert cli_mod._augment_denial_reason(cfg, "Bash", "nope") == "nope"


# --- #17: receipt-write returns success + surfaces a broken sink --------------

def test_write_receipt_returns_true_on_success(cli_mod, bound, monkeypatch):
    monkeypatch.setattr(cli_mod, "RECEIPTS", cli_mod.STATE / "receipts.jsonl", raising=False)
    assert cli_mod.write_receipt({"phase": "pre", "decision": "allow"}) is True
    assert cli_mod.receipt_sink_failure() is None


def test_write_receipt_signs_and_hash_chains(cli_mod, bound, monkeypatch):
    monkeypatch.setattr(cli_mod, "RECEIPTS", cli_mod.STATE / "receipts.jsonl", raising=False)
    assert cli_mod.write_receipt({"phase": "pre", "decision": "allow"}) is True
    assert cli_mod.write_receipt({"phase": "pre", "decision": "deny"}) is True

    rows = [json.loads(line) for line in cli_mod.RECEIPTS.read_text().splitlines()]
    ok, errors = cli_mod.verify_receipt_rows(rows)

    assert ok, errors
    assert rows[0]["payload"]["prev_hash"] is None
    assert rows[1]["payload"]["prev_hash"] == rows[0]["receipt_hash"]
    assert rows[0]["signer_pub"] == rows[1]["signer_pub"]
    assert rows[0]["signer_pub"] == cli_mod.RECEIPT_PUB.read_text().strip()


def test_receipt_verify_summary_names_checks_and_local_trust(cli_mod, bound, monkeypatch):
    monkeypatch.setattr(cli_mod, "RECEIPTS", cli_mod.STATE / "receipts.jsonl", raising=False)
    assert cli_mod.write_receipt({"phase": "pre", "decision": "allow"}) is True
    rows = [json.loads(line) for line in cli_mod.RECEIPTS.read_text().splitlines()]

    summary = "\n".join(cli_mod.receipt_verify_summary_lines(rows))

    assert "receipt signatures" in summary
    assert "hash chain" in summary
    assert "receipt_pub.hex" in summary
    assert "Local mode" in summary
    assert "tamper-evident" in summary


def test_receipt_verify_failure_summary_does_not_claim_success(cli_mod, bound, monkeypatch):
    monkeypatch.setattr(cli_mod, "RECEIPTS", cli_mod.STATE / "receipts.jsonl", raising=False)
    assert cli_mod.write_receipt({"phase": "pre", "decision": "allow"}) is True
    rows = [json.loads(line) for line in cli_mod.RECEIPTS.read_text().splitlines()]
    rows[0]["payload"]["decision"] = "deny"

    ok, _ = cli_mod.verify_receipt_rows(rows)
    summary = "\n".join(cli_mod.receipt_verify_summary_lines(rows, ok=ok))

    assert ok is False
    assert "Verification checks" in summary
    assert "!! receipt signatures" in summary
    assert "Trust roots" in summary


def test_audit_verify_exits_nonzero_on_integrity_failure(cli_mod, bound, monkeypatch, capsys):
    monkeypatch.setattr(cli_mod, "RECEIPTS", cli_mod.STATE / "receipts.jsonl", raising=False)
    assert cli_mod.write_receipt({"phase": "pre", "decision": "allow"}) is True
    rows = [json.loads(line) for line in cli_mod.RECEIPTS.read_text().splitlines()]
    rows[0]["payload"]["decision"] = "deny"
    cli_mod.RECEIPTS.write_text(json.dumps(rows[0]) + "\n")

    with pytest.raises(SystemExit) as exc:
        cli_mod.cmd_audit(type("Args", (), {"verify": True, "tail": None})())

    out = capsys.readouterr().out
    assert exc.value.code == 1
    assert "Receipt verification FAILED" in out
    assert "signature invalid" in out or "receipt_hash mismatch" in out


def test_audit_row_shows_multiple_key_args(cli_mod, bound, monkeypatch, capsys):
    monkeypatch.setattr(cli_mod, "RECEIPTS", cli_mod.STATE / "receipts.jsonl", raising=False)
    cli_mod.ensure_state_dir()
    cli_mod.RECEIPTS.write_text(json.dumps({
        "payload": {
            "phase": "pre",
            "decision": "deny",
            "claude_tool": "MCP",
            "tenuo_tool": "deploy",
            "reason": "constraint failed",
            "args": {
                "target": "prod",
                "path": "/repo/app",
                "url": "https://example.invalid",
                "branch": "main",
            },
        }
    }) + "\n")

    cli_mod.cmd_audit(type("Args", (), {"verify": False, "tail": None})())
    out = capsys.readouterr().out

    assert "path=/repo/app" in out
    assert "url=https://example.invalid" in out
    assert "target=prod" in out


def test_audit_row_shows_mcp_arguments(cli_mod, bound, monkeypatch, capsys):
    monkeypatch.setattr(cli_mod, "RECEIPTS", cli_mod.STATE / "receipts.jsonl", raising=False)
    cli_mod.ensure_state_dir()
    cli_mod.RECEIPTS.write_text(json.dumps({
        "payload": {
            "phase": "pre",
            "decision": "deny",
            "claude_tool": "mcp__github__get_file_contents",
            "tenuo_tool": "get_file_contents",
            "reason": "Constraint not satisfied",
            "args": {"owner": "torvalds", "repo": "linux", "path": "README", "body": "x" * 200},
        }
    }) + "\n")

    cli_mod.cmd_audit(type("Args", (), {"verify": False, "tail": None})())
    out = capsys.readouterr().out

    assert "owner=torvalds path=README repo=linux" in out
    assert "body=" not in out


def test_write_receipt_chain_survives_concurrent_writers(cli_mod, bound, monkeypatch):
    # Native-tool hooks and the MCP proxy write receipts from separate execution
    # contexts. First-use key generation and read-prev-hash + append must be
    # atomic or signatures/chain links can diverge.
    import threading

    monkeypatch.setattr(cli_mod, "RECEIPTS", cli_mod.STATE / "receipts.jsonl", raising=False)
    cli_mod.ensure_state_dir()

    writers, per_writer = 8, 15
    barrier = threading.Barrier(writers)

    def hammer(w):
        barrier.wait()  # maximize overlap on the read-modify-write window
        for i in range(per_writer):
            assert cli_mod.write_receipt({"phase": "pre", "decision": "allow",
                                          "writer": w, "seq": i}) is True

    threads = [threading.Thread(target=hammer, args=(w,)) for w in range(writers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    rows = [json.loads(line) for line in cli_mod.RECEIPTS.read_text().splitlines()]
    assert len(rows) == writers * per_writer  # no torn/dropped lines
    ok, errors = cli_mod.verify_receipt_rows(rows)  # unbroken chain, in file order
    assert ok, errors
    assert {row["signer_pub"] for row in rows} == {cli_mod.RECEIPT_PUB.read_text().strip()}


def test_verify_receipt_rows_rejects_tampering(cli_mod, bound, monkeypatch):
    monkeypatch.setattr(cli_mod, "RECEIPTS", cli_mod.STATE / "receipts.jsonl", raising=False)
    assert cli_mod.write_receipt({"phase": "pre", "decision": "deny"}) is True

    rows = [json.loads(line) for line in cli_mod.RECEIPTS.read_text().splitlines()]
    rows[0]["payload"]["decision"] = "allow"
    ok, errors = cli_mod.verify_receipt_rows(rows)

    assert ok is False
    assert any("signature invalid" in err or "receipt_hash mismatch" in err for err in errors)


def test_verify_receipt_rows_rejects_untrusted_signer(cli_mod, bound, monkeypatch):
    from tenuo import SigningKey

    monkeypatch.setattr(cli_mod, "RECEIPTS", cli_mod.STATE / "receipts.jsonl", raising=False)
    assert cli_mod.write_receipt({"phase": "pre", "decision": "allow"}) is True

    rows = [json.loads(line) for line in cli_mod.RECEIPTS.read_text().splitlines()]
    forged_key = SigningKey.generate()
    payload = dict(rows[0]["payload"])
    sig = forged_key.sign_raw(cli_mod._canonical_receipt_bytes(payload))
    rows[0]["signer_pub"] = forged_key.public_key.to_bytes().hex()
    rows[0]["signature"] = base64.b64encode(sig).decode()
    rows[0]["receipt_hash"] = cli_mod.hashlib.sha256(
        cli_mod._canonical_receipt_bytes(payload) + sig).hexdigest()

    ok, errors = cli_mod.verify_receipt_rows(rows)

    assert ok is False
    assert any("trusted receipt key" in err for err in errors)


def _authz_evidence(cli_mod, tenuo_tool: str, sign_args: dict, *, ts: int | None = None):
    from tenuo import SigningKey, Warrant
    from tenuo_core import encode_warrant_stack

    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    warrant = Warrant.mint_builder().tools(["read_file"]).holder(holder.public_key).mint(issuer)
    stack = encode_warrant_stack([warrant])
    ts = int(time.time()) if ts is None else ts
    pop = warrant.sign(holder, tenuo_tool, sign_args, ts)
    cli_mod.ISSUER_PUB.write_text(issuer.public_key.to_bytes().hex())
    return cli_mod._authorization_receipt_context(
        tenuo_tool, f"/verify/{tenuo_tool}", sign_args, stack,
        base64.b64encode(bytes(pop)).decode(), ts)


def test_verify_receipt_rows_replays_warrant_evidence(cli_mod, bound, monkeypatch):
    monkeypatch.setattr(cli_mod, "RECEIPTS", cli_mod.STATE / "receipts.jsonl", raising=False)
    cli_mod.ensure_state_dir()
    authz = _authz_evidence(cli_mod, "read_file", {})

    assert cli_mod.write_receipt({"phase": "pre", "decision": "allow", "authz": authz}) is True
    rows = [json.loads(line) for line in cli_mod.RECEIPTS.read_text().splitlines()]
    ok, errors = cli_mod.verify_receipt_rows(rows)

    assert ok, errors


def test_verify_receipt_rows_accepts_stale_pop_for_constraint_replay(cli_mod, bound, monkeypatch):
    monkeypatch.setattr(cli_mod, "RECEIPTS", cli_mod.STATE / "receipts.jsonl", raising=False)
    cli_mod.ensure_state_dir()
    authz = _authz_evidence(cli_mod, "read_file", {}, ts=int(time.time()) - 3600)

    assert cli_mod.write_receipt({"phase": "pre", "decision": "allow", "authz": authz}) is True
    rows = [json.loads(line) for line in cli_mod.RECEIPTS.read_text().splitlines()]
    ok, errors = cli_mod.verify_receipt_rows(rows)

    assert ok, errors


def test_verify_receipt_rows_rejects_replay_mismatch(cli_mod, bound, monkeypatch):
    monkeypatch.setattr(cli_mod, "RECEIPTS", cli_mod.STATE / "receipts.jsonl", raising=False)
    cli_mod.ensure_state_dir()
    authz = _authz_evidence(cli_mod, "delete_everything", {})

    assert cli_mod.write_receipt({"phase": "pre", "decision": "allow", "authz": authz}) is True
    rows = [json.loads(line) for line in cli_mod.RECEIPTS.read_text().splitlines()]
    ok, errors = cli_mod.verify_receipt_rows(rows)

    assert ok is False
    assert any("recorded allow but warrant replay denied" in err for err in errors)


def test_verify_receipt_rows_rejects_missing_approval_evidence(cli_mod, bound, monkeypatch):
    monkeypatch.setattr(cli_mod, "RECEIPTS", cli_mod.STATE / "receipts.jsonl", raising=False)
    cli_mod.ensure_state_dir()
    authz = _authz_evidence(cli_mod, "read_file", {})
    authz["approval_required"] = True

    assert cli_mod.write_receipt({"phase": "pre", "decision": "allow", "authz": authz}) is True
    rows = [json.loads(line) for line in cli_mod.RECEIPTS.read_text().splitlines()]
    ok, errors = cli_mod.verify_receipt_rows(rows)

    assert ok is False
    assert any("approval evidence missing" in err for err in errors)


def test_write_receipt_failure_marks_sink(cli_mod, bound, monkeypatch):
    # Make the append fail without breaking the sibling marker write: point RECEIPTS
    # at a *directory*, so open("a") raises but `.receipt_write_failed` (same parent)
    # is still writable. The call must return False AND record the marker so
    # status/check can surface a broken audit trail.
    cli_mod._receipt_write_warned = False
    receipts = cli_mod.STATE / "receipts.jsonl"
    receipts.mkdir(parents=True)  # a dir where a file is expected
    monkeypatch.setattr(cli_mod, "RECEIPTS", receipts, raising=False)
    assert cli_mod.write_receipt({"phase": "pre", "decision": "allow"}) is False
    assert cli_mod.receipt_sink_failure()  # non-empty marker recorded


def test_write_receipt_clears_marker_on_recovery(cli_mod, bound, monkeypatch):
    # A stale failure marker must be removed once the sink is writable again.
    monkeypatch.setattr(cli_mod, "RECEIPTS", cli_mod.STATE / "receipts.jsonl", raising=False)
    cli_mod.ensure_state_dir()
    cli_mod._receipt_fail_marker().write_text("old failure")
    assert cli_mod.write_receipt({"phase": "pre", "decision": "allow"}) is True
    assert cli_mod.receipt_sink_failure() is None
