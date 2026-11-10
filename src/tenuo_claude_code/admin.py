#!/usr/bin/env python3
"""tenuo-claude-admin — the ADMIN/setup plane for Claude Code governance.

Separation of duties: this is the ONLY place that holds a tenant-admin Cloud
key and the ONLY code that performs admin actions (create agent, create/patch
trigger). Run by tenant administrators or CI — not by the developer or
the agent. The runtime CLI (``tenuo-claude``) has no path to these endpoints
and refuses to run if an admin key is reachable from its environment.

Credentials
-----------
  * Tenant-admin API key (admin actions): read from $TENUO_ADMIN_KEY /
    $TENUO_ADMIN_API_KEY, or from ~/.tenuo/admin.env. NEVER from .state/cloud.env.
  * Runtime / authorizer API key + control-plane URL: read from .state/cloud.env.
    Used for agent claim + trigger fire so the trigger locks to the runtime
    service account (the identity that actually fires at session start), not the
    admin one.

Usage
-----
  TENUO_ADMIN_KEY=tc_... tenuo-admin setup          # or put it in ~/.tenuo/admin.env
  tenuo-admin show
"""
from __future__ import annotations

import argparse
import base64
import getpass
import os
import socket
import time
from pathlib import Path

import sys

import tenuo_claude_code.cli as tc
from tenuo_claude_code.paths import ADMIN_COMMAND, bind_project_paths

ADMIN_ENV = Path.home() / ".tenuo" / "admin.env"


def agent_name(cfg: dict) -> str:
    """Per-developer holder-agent name, DISTINCT from the authorizer name.

    Defaults to `claude-code-<user>@<host>` so each developer/machine shows up
    as its own agent in the control plane (richer audit attribution) and never
    collides with the authorizer resource (which keeps `cfg.name`). Override via
    tenuo.yaml `cloud.agent_name`.
    """
    explicit = (cfg.get("cloud") or {}).get("agent_name")
    if explicit:
        return str(explicit)[:64]
    user = (getpass.getuser() or "dev").strip() or "dev"
    host = (socket.gethostname() or "host").split(".")[0] or "host"
    return f"claude-code-{user}@{host}"[:64]


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

def admin_creds(cfg: dict) -> dict:
    """Admin key from env/~/.tenuo/admin.env; URL + authorizer key from cloud.env."""
    runtime = tc.cloud_creds(cfg)  # url, api_key (authorizer), root — no admin key
    admin_key = os.environ.get("TENUO_ADMIN_KEY") or os.environ.get("TENUO_ADMIN_API_KEY")
    if not admin_key and ADMIN_ENV.exists():
        af = tc.read_env_file(ADMIN_ENV)
        admin_key = af.get("TENUO_ADMIN_KEY") or af.get("TENUO_ADMIN_API_KEY")
    return {**runtime, "admin_key": admin_key}


# ---------------------------------------------------------------------------
# Policy -> trigger warrant_config translation (admin-only)
# ---------------------------------------------------------------------------

def to_wire_constraint(spec: str, sandbox: str):
    """Constraint DSL string -> Cloud trigger {"_type","_value"} JSON.

    Emits the wire form the trigger API expects (server maps these to
    tenuo-core constraint type IDs).
    """
    spec = spec.replace("{sandbox}", sandbox)
    kind, _, rest = spec.partition(":")
    if kind == "subpath":
        return {"_type": "subpath", "_value": rest}
    if kind == "shlex":
        return {"_type": "shlex", "_value": [v.strip() for v in rest.split(",") if v.strip()]}
    if kind == "regex":
        return {"_type": "regex", "_value": rest}
    if kind == "pattern":
        return {"_type": "pattern", "_value": rest}
    if kind == "oneof":
        return {"_type": "one_of", "_value": [v.strip() for v in rest.split(",")]}
    if kind == "notoneof":
        return {"_type": "not_one_of", "_value": [v.strip() for v in rest.split(",")]}
    if kind == "exact":
        return {"_type": "exact", "_value": rest}
    if kind == "urlpattern":
        return {"_type": "url_pattern", "_value": rest}
    if kind == "cidr":
        return {"_type": "cidr", "_value": rest}
    if kind == "range":
        # Reuse the local validator so Cloud rejects the same specs (a missing
        # comma or a blank-both `range:,` would otherwise serialize to `..` =
        # match-all). The trigger API parses a STRING with a `..` separator.
        lo, hi = tc.parse_range_spec(spec)
        lo_s = "" if lo is None else lo
        hi_s = "" if hi is None else hi
        return {"_type": "range", "_value": f"{lo_s}..{hi_s}"}
    raise SystemExit(f"Unknown constraint kind '{kind}' in '{spec}'")


def domains_to_exempt_regex(domains: list[str]) -> dict:
    """Allowlisted domains -> a single `regex` constraint for an Exempt gate.

    The approval gate uses `Exempt(<constraint>)`: hosts matching it skip approval.
    Tenuo-core rejects `any`/`wildcard`/`not` as Exempt inner constraints (they have
    identity-only subsumption and would freeze delegation), so a multi-domain
    allowlist can't be an AnyOf — we fold it into ONE anchored regex instead. The
    allowlist's `*` matches a single label (same as the Pattern host constraint),
    so it maps to `[^.]+`.
    """
    import re
    alts = [re.escape(d).replace(r"\*", r"[^.]+") for d in domains]
    return {"_type": "regex", "_value": "^(?:" + "|".join(alts) + ")$"}


def url_safe_ssrf_wire(policy: dict) -> dict:
    """Structured `url_safe` for Cloud triggers: SSRF hygiene only, no domain allowlist.

    Domain control lives elsewhere — on the separate `host` constraint in strict
    mode, or on the approval gate's Exempt regex when human approval is enabled.
    Passing a bare domain list as `_value` is the legacy form and pins
    `allow_domains` on the url arg, which blocks off-allowlist URLs at the
    constraint layer before they can reach the approval gate.
    """
    schemes = [str(s) for s in policy.get("schemes") or
               (["https"] if not policy.get("cidrs") else ["http", "https"])]
    value = {
        "schemes": schemes,
        # Explicit null — omitting the key makes Cloud default to [], which
        # blocks every domain. Null means "no domain allowlist" (SSRF-only).
        "allow_domains": None,
        "block_private": not bool(policy.get("cidrs")),
        "block_loopback": True,
        "block_metadata": True,
        "block_reserved": True,
    }
    # tenuo-core UrlSafe.allow_ports is honoured by Cloud (mirrors local
    # make_web_constraints); omit when unset so any port is allowed. Shared
    # validator rejects malformed ports identically to local mint.
    ports = tc.parse_ports(policy)
    if ports:
        value["allow_ports"] = ports
    return {"_type": "url_safe", "_value": value}


def web_to_wire(policy: dict):
    """WebFetch org policy -> trigger constraints for the `url` and `host` args.

    Mirrors the local two-field design (make_web_constraints): `url` is url_safe
    (secure defaults block private/loopback/metadata/encoded IPs), `host` is an
    AnyOf of the allowed domains (Pattern) and IP ranges (Cidr) so the hostname
    the hook extracts is matched explicitly. Both fields must be present because
    resolve_tool always sends {url, host}.

    When `cidrs` are set, url_safe_ssrf_wire permits private ranges and plain
    http so internal egress works — same as local. For non-WebFetch IP-based
    tools, use the standalone `cidr:` constraint instead.
    """
    domains = [str(d) for d in policy.get("domains") or []]
    cidrs = [str(c) for c in policy.get("cidrs") or []]
    if not domains and not cidrs:
        raise SystemExit("WebFetch cloud policy needs at least one domain or cidr")
    host_alts = ([{"_type": "pattern", "_value": d} for d in domains]
                 + [{"_type": "cidr", "_value": c} for c in cidrs])
    # Structured url_safe with explicit allow_domains (not the legacy bare-list
    # `_value`) so Cloud/core honour the full SSRF field set. None when only
    # cidrs are used — the host Cidr members carry the IP allowlist instead.
    url_val = url_safe_ssrf_wire(policy)
    url_val["_value"]["allow_domains"] = domains or None
    return {
        "url": url_val,
        "host": {"_type": "any", "_value": host_alts},
    }


def build_warrant_config(cfg: dict, approval_policy_id: str | None = None) -> dict:
    """Translate tenuo.yaml `enforce` (+ mcp) into a trigger warrant_config.

    actions = capability names; per_action_constraints = {cap: {arg: wire}}.

    The holder is DYNAMIC (`${event.agent_id}`): the firing side passes its own
    registered agent id at fire time, so one trigger serves many per-developer
    agents and each warrant binds to that developer's claimed key (PoP). A static
    holder would bind every developer's warrant to one key and break PoP for all
    but one.

    When WebFetch.approval and/or mcp.enforce approval blocks are linked to a Cloud
    policy, gated capabilities relax to wildcard args with approval_gates (and Exempt
    sub-constraints where configured).
    """
    sandbox = cfg["_sandbox_abs"]
    gov = tc.governed_map(cfg)
    approval = tc.webfetch_approval(cfg)
    gate_webfetch = bool(approval and approval_policy_id)
    per_action: dict = {}
    approval_gates: dict = {}
    for g in gov.values():
        cap = g["cap"]
        if cap in per_action:
            continue
        if "web" in g:
            if gate_webfetch:
                domains = [str(d) for d in g["web"].get("domains") or []]
                per_action[cap] = {
                    "url": url_safe_ssrf_wire(g["web"]),
                    "host": {"_type": "wildcard"},
                }
                approval_gates[cap] = {
                    "args": {"host": {"exempt": domains_to_exempt_regex(domains)}}}
            else:
                per_action[cap] = web_to_wire(g["web"])
        elif g.get("approval"):
            # Native human-approval gate. The arg relaxes to a wildcard (the
            # capability grants the call) and approval is enforced by the gate.
            # With a user `exempt:`, gate the arg with an Exempt constraint (approve
            # unless the arg matches the exemption). Without one, use a whole-tool
            # gate (args: None) — tenuo-core's first-class "every invocation requires
            # approval" — rather than a never-matching exempt sentinel.
            # Needs a Cloud approval policy; without one, leave ungranted (deny).
            if approval_policy_id:
                arg = g["arg"]
                per_action[cap] = {arg: {"_type": "wildcard"}}
                if g.get("exempt"):
                    approval_gates[cap] = {"args": {arg: {
                        "exempt": to_wire_constraint(g["exempt"], sandbox)}}}
                else:
                    approval_gates[cap] = {"args": None}
        else:
            per_action[cap] = {g["arg"]: to_wire_constraint(g["spec"], sandbox)}
    gate_approval = bool(approval_policy_id)
    for mtool, raw in (cfg.get("mcp", {}).get("enforce") or {}).items():
        cap = tc.mcp_capability(cfg, mtool)
        if cap in per_action:
            continue
        parsed = tc.parse_mcp_enforce_spec(raw)
        cons = parsed["constraints"]
        approval = parsed.get("approval")
        exempt_args = parsed.get("exempt_args") or {}
        if cons and approval and not gate_approval:
            continue  # never grant a gated action without a linked approval policy
        if cons:
            # Explicit constraints are the capability ceiling; approval adds a
            # human gate on top without broadening the allowed argument space.
            per_action[cap] = {a: to_wire_constraint(spec, sandbox) for a, spec in cons.items()}
            if approval and gate_approval:
                gate_args: dict = {}
                for ek, es in exempt_args.items():
                    gate_args[ek] = {"exempt": to_wire_constraint(es, sandbox)}
                approval_gates[cap] = {"args": gate_args or None}
            continue

        if approval and gate_approval:
            # Approval-only tools need a wildcard grant so the authorizer can
            # reach the gate; the approval signature still binds exact args.
            gated = list(exempt_args.keys()) or [tc.mcp_default_arg(mtool)]
            per_action[cap] = {a: {"_type": "wildcard"} for a in gated}
            gate_args: dict = {}
            for ek, es in exempt_args.items():
                gate_args[ek] = {"exempt": to_wire_constraint(es, sandbox)}
            approval_gates[cap] = {"args": gate_args or {a: {} for a in gated}}
    for constraints in per_action.values():
        constraints[tc.REQUEST_FIELD] = {"_type": "wildcard"}
    # ALLOW capabilities (unconstrained): the hook routes allow-listed tools to
    # /verify/<cap>, so the warrant must GRANT them or every WebSearch/TodoWrite/…
    # is denied in enforce mode.
    for cap in tc.audit_map(cfg).values():
        per_action.setdefault(cap, {})
    # default: approve -> grant the catch-all cap WITH an approval gate, so any
    # tool not in enforce/allow pauses for human sign-off (Cloud-only; local
    # warrants never grant the catch-all, so local `approve` falls back to deny).
    # Needs a linked Cloud approval policy; without one we leave it ungranted (deny).
    if tc.default_mode(cfg) == "approve" and approval_policy_id:
        # Whole-tool gate (args: None) = tenuo-core's first-class "every invocation
        # requires approval", so every unlisted tool pauses for sign-off. The cap
        # wildcards `tool` (resolve_tool signs the tool name) purely so the approval's
        # request_hash binds per tool name — approving one unlisted tool must not
        # auto-approve another — not to make the gate fire.
        per_action.setdefault(tc.CATCHALL_AUDIT, {"tool": {"_type": "wildcard"}, tc.REQUEST_FIELD: {"_type": "wildcard"}})
        approval_gates.setdefault(tc.CATCHALL_AUDIT, {"args": None})
    # Subagent spawn: a signed capability whose subagent_type is constrained to
    # the declared roles. Lets the runtime route the Agent/Task spawn through the
    # authorizer for a root-signed decision (instead of a local-only policy gate).
    roles = tc.subagent_roles(cfg)
    if roles:
        per_action["spawn_agent"] = {
            "subagent_type": {"_type": "one_of", "_value": list(roles.keys())}}
    wc = {
        "holder": "${event.agent_id}",
        "actions": sorted(per_action.keys()),
        "per_action_constraints": per_action,
        "ttl": tc.session_ttl_seconds(cfg),
        # max_depth=1 permits exactly ONE attenuation: the session warrant
        # (depth 0) -> a subagent child (depth 1, terminal). Core enforces this
        # cryptographically on every WarrantStack — a child can't sub-delegate
        # (depth 2 is rejected). This is the real, verified delegation limit.
        "max_depth": 1,
    }
    if approval_gates:
        # `_policy_id` links the gate to the Cloud approval policy: at fire time
        # the control plane pulls the policy's approver keys + threshold INTO the
        # issued warrant, so it's self-contained for offline approval verification.
        approval_gates["_policy_id"] = approval_policy_id
        wc["approval_gates"] = approval_gates
    return wc


# ---------------------------------------------------------------------------
# WebFetch human-approval: resolve the approver identity + Cloud approval policy
# ---------------------------------------------------------------------------

def resolve_approver_identity(url: str, admin: str, selector: str, *, by_id: bool = False) -> tuple[str, str, str]:
    """Find an EXISTING Cloud identity binding -> (id, display_name, public_key_hex).

    The identity carries the approver's KMS public key and notification routing on
    their configured channel. Setup only references an existing identity; it does
    not create or mutate identities in Cloud. Fails loudly if absent or keyless.

    Prefer ``cloud.approver_identity_id`` for durable team configs. Display-name
    lookup remains supported for demos and quickstarts.
    """
    status, body = tc.cloud_api("GET", url, admin, "/v1/identities")
    if status != 200 or not isinstance(body, dict):
        raise SystemExit(f"List identities failed ({status}): {body}")
    identities = body.get("identities") or []
    selector = selector.strip()
    if by_id:
        matches = [i for i in identities if str(i.get("id", "")).strip() == selector]
    else:
        matches = [i for i in identities
                   if str(i.get("display_name", "")).strip() == selector]
    if not matches:
        field = "cloud.approver_identity_id" if by_id else "cloud.approver_identity"
        kind = "id" if by_id else "display name"
        raise SystemExit(
            f"No Cloud identity with {kind} '{selector}' ({field}).\n"
            "  Create an identity binding in the dashboard first:\n"
            "    https://docs.tenuo.ai/guides/adding-channels\n"
            "    https://docs.tenuo.ai/integrations/identity-bindings\n"
            "  Dashboard -> Channels -> Identity Bindings.")
    if not by_id and len(matches) > 1:
        raise SystemExit(
            f"Multiple Cloud identities are named '{selector}'.\n"
            "  Set cloud.approver_identity_id to the stable identity id instead.")
    ident = matches[0]
    pub = str(ident.get("public_key") or "")
    if not pub:
        raise SystemExit(f"Identity '{selector}' has no public key - it can't sign approvals.")
    return str(ident["id"]), str(ident.get("display_name") or selector), pub


def ensure_session_approval_policy(url: str, admin: str, name: str, threshold: int,
                                   approver_key: str, identity_id: str) -> str:
    """Create-or-reuse a session-wide approval policy and link the approver. -> policy_id.

    One policy covers every gated capability (native hook + MCP proxy). The policy
    holds the approver key set + threshold + TTL; linking the identity routes the
    prompt to the human. Idempotent.
    """
    status, body = tc.cloud_api("GET", url, admin, "/v1/approvals/policies")
    existing = None
    if status == 200 and isinstance(body, dict):
        for p in body.get("policies") or []:
            if str(p.get("name", "")) == name:
                existing = p
                break
    policy_body = {
        "name": name,
        "description": "Claude Code session: human approval for gated tool calls",
        "tool_pattern": "*",
        "threshold": int(threshold),
        "approver_keys": [approver_key],
        "ttl_seconds": 300,
        "escalation_after_seconds": 60,
    }
    if existing:
        policy_id = str(existing["id"])
        s, b = tc.cloud_api("PATCH", url, admin, f"/v1/approvals/policies/{policy_id}",
                            {"threshold": int(threshold), "approver_keys": [approver_key],
                             "enabled": True})
        if s not in (200, 201):
            raise SystemExit(f"Update approval policy failed ({s}): {b}")
        print(f"  approval : policy {policy_id} '{name}' (reused)")
    else:
        s, b = tc.cloud_api("POST", url, admin, "/v1/approvals/policies", policy_body)
        if s not in (200, 201) or not isinstance(b, dict) or not b.get("id"):
            raise SystemExit(f"Create approval policy failed ({s}): {b}")
        policy_id = str(b["id"])
        print(f"  approval : policy {policy_id} '{name}' (created)")
    # Link the identity so the approver is notified and authorized to sign.
    # Treat already-linked (409/422) as success.
    s, b = tc.cloud_api("POST", url, admin, f"/v1/identities/{identity_id}/add-to-policy",
                        {"policy_id": policy_id})
    if s not in (200, 201, 204, 409, 422):
        raise SystemExit(f"Link approver to policy failed ({s}): {b}")
    return policy_id


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def ensure_agent_trigger_binding(url: str, admin: str, agent_id: str, tid: str) -> bool:
    """Ensure an adopted agent is allowed to fire the resolved trigger."""
    status, cur = tc.cloud_api("GET", url, admin, f"/v1/agents/{agent_id}")
    if status != 200 or not isinstance(cur, dict):
        raise SystemExit(f"Inspect agent failed ({status}): {cur}")
    cur_trigs = cur.get("allowed_triggers")
    if cur_trigs and tid in cur_trigs:
        return False
    s3, b3 = tc.cloud_api("PATCH", url, admin, f"/v1/agents/{agent_id}",
                          {"allowed_triggers": [tid]})
    if s3 not in (200, 201):
        raise SystemExit(f"Reconcile agent trigger binding failed ({s3}): {b3}")
    return True


def ensure_agent_holder_claimed(url: str, api_key: str, admin: str,
                                agent_id: str, holder_hex: str) -> bool:
    """Re-claim the holder public key when local material drifted from Cloud."""
    status, cur = tc.cloud_api("GET", url, admin, f"/v1/agents/{agent_id}")
    if status != 200 or not isinstance(cur, dict):
        raise SystemExit(f"Inspect agent failed ({status}): {cur}")
    cloud_hex = (cur.get("public_key") or "").lower()
    if cloud_hex and cloud_hex == holder_hex.lower():
        return False
    s, rot = tc.cloud_api("POST", url, admin, f"/v1/agents/{agent_id}/rotate", {})
    if s not in (200, 201) or not isinstance(rot, dict):
        raise SystemExit(f"Rotate key for re-claim failed ({s}): {rot}")
    reg_token = rot["registration_token"]
    s2, body = tc.cloud_api("POST", url, api_key, "/v1/agents/claim",
                            {"agent_id": agent_id, "public_key": holder_hex,
                             "registration_token": reg_token})
    if s2 != 200:
        hint = ""
        if s2 == 403:
            hint = (
                "\n  cloud.env in the state directory (`tenuo-claude state-dir`) must hold the Quick Connect / authorizer "
                "runtime key (RBAC: agent claim + trigger fire), not the admin key.")
        raise SystemExit(f"Re-claim agent failed ({s2}): {body}{hint}")
    return True


def cmd_setup(_args) -> None:
    """One-time: register the holder agent + create the trigger from tenuo.yaml.

    Admin key creates the agent + trigger. The runtime key in cloud.env
    claims the holder key and fires (so the trigger locks to the runtime SA).
    Idempotent: re-running reuses the agent and updates the trigger.
    """
    from tenuo import SigningKey

    cfg = tc.load_config()
    creds = admin_creds(cfg)
    if not creds["url"] or not creds["api_key"]:
        raise SystemExit(
            "Set runtime Cloud credentials in cloud.env in the state directory (`tenuo-claude state-dir`):\n"
            "  TENUO_CONNECT_TOKEN (Quick Connect) or TENUO_CONTROL_PLANE_URL + TENUO_API_KEY")
    if not creds["admin_key"]:
        raise SystemExit(
            "tenuo-admin setup needs a tenant-admin API key.\n"
            "  export TENUO_ADMIN_KEY=tc_...   (or add it to ~/.tenuo/admin.env)")

    url, api_key, admin = creds["url"], creds["api_key"], creds["admin_key"]
    state = tc.load_cloud_state()
    authz_name = cfg.get("name", "tenuo-claude")   # authorizer / PEP resource name
    aname = agent_name(cfg)                             # distinct, per-developer holder
    # Resolve a USABLE trigger id before creating the agent (the agent binds
    # allowed_triggers=[tid]). Cloud soft-deletes triggers: a deleted id is
    # permanently burned (Create -> 409, Update -> trigger_deleted), so on
    # re-onboarding we fall back to a fresh, unique sibling id.
    tid = state.get("trigger_id") or tc.trigger_id(cfg) or f"trig_{tc.slug(authz_name)}"
    s_probe, info_probe = tc.cloud_api("GET", url, admin, f"/v1/triggers/{tid}")
    if s_probe == 200 and isinstance(info_probe, dict):
        if info_probe.get("status") == "deleted":
            tid = f"{tid}_{int(time.time())}"   # burned id; derive a fresh one
            trigger_exists = False
        else:
            trigger_exists = True               # active/paused -> update in place
    else:
        trigger_exists = False                  # 404 / unknown -> create fresh

    # Holder keypair (reuse init's holder key so PoP matches the claimed key).
    if not tc.HOLDER_KEY.exists():
        tc.ensure_state_dir()
        holder = SigningKey.generate()
        tc.write_secret(tc.HOLDER_KEY, base64.b64encode(bytes(holder.secret_key_bytes())).decode())
    else:
        holder = SigningKey.from_bytes(base64.b64decode(tc.HOLDER_KEY.read_text()))
    holder_hex = holder.public_key.to_bytes().hex()

    # 1) Agent — create (admin) or reuse. Named per-developer and bound to this
    #    trigger (allowed_triggers) so it can only ever hold warrants from it.
    agent_id = state.get("agent_id")
    if not agent_id:
        create_body = {"name": aname, "allowed_triggers": [tid],
                       "description": f"Claude Code holder for {aname}"}
        status, body = tc.cloud_api("POST", url, admin, "/v1/agents", create_body)
        code = (body.get("error") or {}).get("code") if isinstance(body, dict) else None
        if status == 409 and code == "agent_name_parked":
            # Name was held by a revoked agent (e.g. a prior wipe / re-onboard).
            # Reclaim it: Cloud issues a fresh agent id + registration token.
            status, body = tc.cloud_api("POST", url, admin, "/v1/agents",
                                        {**create_body, "reuse_revoked_name": True})
        if status == 201:
            agent_id, reg_token = body["id"], body["registration_token"]
        elif status == 409:
            # Name is taken in Cloud but local state was wiped (or never saved).
            # Active -> rotate key and re-claim; revoked/parked -> reclaim name.
            s, info = tc.cloud_api("GET", url, admin, f"/v1/agents/by-name/{aname}")
            if s != 200 or not isinstance(info, dict):
                raise SystemExit(f"Agent '{aname}' exists but could not be adopted ({s}): {info}")
            agent_id = info["id"]
            agent_status = (info.get("status") or "").lower()
            if agent_status == "pending":
                # Stuck mid-rotation (rotate issued a token but claim never ran).
                # Delete and recreate — cannot rotate or reuse while pending.
                s_del, del_body = tc.cloud_api("DELETE", url, admin, f"/v1/agents/{agent_id}")
                if s_del not in (200, 204):
                    raise SystemExit(
                        f"Agent '{aname}' is pending (incomplete claim); "
                        f"delete failed ({s_del}): {del_body}")
                status, body = tc.cloud_api("POST", url, admin, "/v1/agents", create_body)
                park = (body.get("error") or {}).get("code") if isinstance(body, dict) else None
                if status == 409 and park == "agent_name_parked":
                    status, body = tc.cloud_api("POST", url, admin, "/v1/agents",
                                                {**create_body, "reuse_revoked_name": True})
                if status != 201:
                    raise SystemExit(
                        f"Agent '{aname}' was pending; recreate failed ({status}): {body}")
                agent_id, reg_token = body["id"], body["registration_token"]
                print(f"  agent    : {agent_id} '{aname}' (replaced pending agent)")
            elif agent_status != "active":
                status, body = tc.cloud_api("POST", url, admin, "/v1/agents",
                                            {**create_body, "reuse_revoked_name": True})
                if status != 201:
                    raise SystemExit(
                        f"Agent '{aname}' is {agent_status or 'not active'}; "
                        f"reuse_revoked_name failed ({status}): {body}")
                agent_id, reg_token = body["id"], body["registration_token"]
                print(f"  agent    : {agent_id} '{aname}' (reclaimed {agent_status} name)")
            else:
                s, rot = tc.cloud_api("POST", url, admin, f"/v1/agents/{agent_id}/rotate", {})
                if s not in (200, 201) or not isinstance(rot, dict):
                    rot_code = (rot.get("error") or {}).get("code") if isinstance(rot, dict) else None
                    if rot_code == "agent_not_active":
                        status, body = tc.cloud_api("POST", url, admin, "/v1/agents",
                                                    {**create_body, "reuse_revoked_name": True})
                        if status != 201:
                            raise SystemExit(
                                f"Agent '{aname}' is not active; "
                                f"reuse_revoked_name failed ({status}): {body}")
                        agent_id, reg_token = body["id"], body["registration_token"]
                        print(f"  agent    : {agent_id} '{aname}' (reclaimed inactive name)")
                    else:
                        raise SystemExit(f"Rotate key for '{aname}' failed ({s}): {rot}")
                else:
                    reg_token = rot["registration_token"]
                    print(f"  agent    : {agent_id} '{aname}' (adopted existing; key rotated)")
        else:
            raise SystemExit(f"Create agent failed ({status}): {body}")
        # 2) Claim — bind the holder public key (hex). Runtime key (Quick Connect).
        status, body = tc.cloud_api("POST", url, api_key, "/v1/agents/claim",
                                    {"agent_id": agent_id, "public_key": holder_hex,
                                     "registration_token": reg_token})
        if status != 200:
            hint = ""
            if status == 403:
                hint = (
                    "\n  cloud.env in the state directory (`tenuo-claude state-dir`) must hold the Quick Connect / authorizer "
                    "runtime key (RBAC: agent claim + trigger fire), not the admin key.")
            raise SystemExit(f"Claim agent failed ({status}): {body}{hint}")
        if ensure_agent_trigger_binding(url, admin, agent_id, tid):
            print(f"  agent    : {agent_id} '{aname}' (allowed trigger reconciled)")
        print(f"  agent    : {agent_id} '{aname}' (registered + key claimed)")
        tc.save_cloud_state({"agent_id": agent_id, "agent_name": aname})
    else:
        # Reuse. Reconcile the per-developer name AND allowed_triggers so the
        # agent can fire the resolved trigger (the id may have changed if a prior
        # trigger was deleted). Keeps issuance history; just fixes name + binding.
        _, cur = tc.cloud_api("GET", url, admin, f"/v1/agents/{agent_id}")
        cur_name = cur.get("name") if isinstance(cur, dict) else None
        patch = {}
        if cur_name != aname:
            patch["name"] = aname
        if patch:
            s3, b3 = tc.cloud_api("PATCH", url, admin, f"/v1/agents/{agent_id}", patch)
            if s3 in (200, 201):
                tc.save_cloud_state({"agent_name": aname})
                print(f"  agent    : {agent_id} '{aname}' (reused; reconciled {', '.join(patch)})")
            else:
                raise SystemExit(f"Reconcile agent failed ({s3}): {b3}")
        else:
            print(f"  agent    : {agent_id} '{aname}' (reused)")
        if ensure_agent_trigger_binding(url, admin, agent_id, tid):
            print(f"  agent    : {agent_id} '{aname}' (allowed trigger reconciled)")
        if ensure_agent_holder_claimed(url, api_key, admin, agent_id, holder_hex):
            print(f"  agent    : {agent_id} '{aname}' (holder key re-claimed)")
            tc.save_cloud_state({"holder_pub_hex": holder_hex})

    # 2b) Human approval (optional): resolve the configured approver identity and
    #     create/reuse one session-wide Cloud approval policy so the trigger can
    #     bake approver KMS keys + per-capability gates into every warrant.
    gates = tc.approval_entries(cfg)
    approval_policy_id = None
    if gates:
        cloud_cfg = cfg.get("cloud") or {}
        approver_id_cfg = cloud_cfg.get("approver_identity_id")
        approver_name_cfg = cloud_cfg.get("approver_identity")
        approver_selector = approver_id_cfg or approver_name_cfg
        if not approver_selector:
            raise SystemExit(
                "Approval gates are configured but cloud.approver_identity_id or "
                "cloud.approver_identity is missing.")
        identity_id, approver_name, approver_key = resolve_approver_identity(
            url, admin, str(approver_selector), by_id=bool(approver_id_cfg))
        threshold = max(int(g[1].get("threshold", 1)) for g in gates)
        approval_policy_id = ensure_session_approval_policy(
            url, admin, f"{tc.slug(authz_name)}-session-approval",
            threshold, approver_key, identity_id)
        gated = ", ".join(g[0] for g in gates)
        tc.save_cloud_state({
            "session_approval_policy_id": approval_policy_id,
            "web_fetch_approval_policy_id": approval_policy_id,
            "web_fetch_approver": approver_name,
            "approver_identity_id": identity_id,
            "approval_gates": [g[0] for g in gates],
        })
        print(f"  approval : {gated} -> '{approver_name}' ({identity_id}) ({approver_key[:16]}…)")

    # 3) Trigger — create or update with the warrant_config from tenuo.yaml.
    wc = build_warrant_config(cfg, approval_policy_id)
    # Start permissive on the initiator so the first fire succeeds; we lock it
    # to the discovered service account below.
    if trigger_exists:
        status, body = tc.cloud_api("PATCH", url, admin, f"/v1/triggers/{tid}",
                                    {"warrant_config": wc, "status": "active",
                                     "initiators": {"skip_initiator_allowlist": True}})
        if status not in (200, 201):
            raise SystemExit(f"Update trigger failed ({status}): {body}")
        print(f"  trigger  : {tid} (updated)")
    else:
        create_body = {"id": tid, "name": f"{authz_name} — session warrant",
                       "warrant_config": wc,
                       "initiators": {"skip_initiator_allowlist": True}}
        status, body = tc.cloud_api("POST", url, admin, "/v1/triggers", create_body)
        if status not in (200, 201):
            raise SystemExit(f"Create trigger failed ({status}): {body}")
        print(f"  trigger  : {tid} (created)")
    # Record the policy fingerprint baked into this trigger so a later
    # `tenuo-claude refresh` can detect capability drift and tell the user to
    # re-run setup (Cloud warrants come from the trigger, not from refresh).
    tc.save_cloud_state({"trigger_id": tid,
                         "policy_fingerprint": tc.policy_capability_fingerprint(cfg)})

    # 4) Dry-run fire — validate before issuing.
    event = {"sandbox": cfg["_sandbox_abs"], "agent_id": agent_id}
    status, body = tc.cloud_api("POST", url, api_key, f"/v1/triggers/{tid}/fire",
                                {"event_data": event, "dry_run": True})
    dr = (body or {}).get("dry_run", {}) if isinstance(body, dict) else {}
    if status != 200 or not dr.get("would_issue", False):
        raise SystemExit(f"Dry-run fire not OK ({status}): {body}")
    print("  dry-run  : would_issue=true, no validation issues")

    # 5) Real fire (authorizer key) — and discover the runtime SA from the warrant.
    warrant_b64, root = tc.fire_session_warrant(cfg, creds)
    tc.write_secret(tc.WARRANT, warrant_b64)
    sa = None
    try:
        from tenuo import Warrant
        raw = Warrant.from_base64(warrant_b64).extension("tenuo.initiator_identity")
        sa = raw.decode() if isinstance(raw, (bytes, bytearray)) else raw
    except Exception:
        pass
    print(f"  fired    : warrant issued, signed by tenant root {root[:16]}…")

    # 6) Lock the initiator policy to the discovered service account (RBAC).
    if sa:
        sa_name = sa[3:] if sa.startswith("sa:") else sa
        status, body = tc.cloud_api("PATCH", url, admin, f"/v1/triggers/{tid}",
                                    {"initiators": {"allowed_service_accounts": [sa_name]}})
        if status in (200, 201):
            tc.save_cloud_state({"service_account": sa_name})
            print(f"  locked   : initiators -> service account '{sa_name}'")
        else:
            print(f"  warning  : could not lock initiators ({status}); temporary initiator bypass remains")
    else:
        print("  warning  : could not read initiator identity from warrant; temporary initiator bypass remains")

    tc.save_cloud_state({"holder_pub_hex": holder_hex, "root": root})
    # Persist the managed bit in CLOUD STATE (not local policy) so enterprise
    # rollout — not an editable tenuo.yaml — is the authority for managed mode.
    if getattr(_args, "managed", False):
        tc.save_cloud_state({"managed": True, "local_policy": "attenuate_only"})
        print("  managed  : org-managed mode recorded (Cloud authority; local attenuates only)")
    reloaded = tc.sync_runtime_artifacts(cfg, restart_authorizer=tc.authorizer_running(cfg))
    print(f"\nSetup complete. `tenuo-claude up` now fires {tid} for a root-signed session warrant.")
    if reloaded:
        print("  local     : gateway synced; authorizer reloaded")
    else:
        print("  local     : gateway synced — run `tenuo-claude up` if the authorizer is down")


def cmd_show(_args) -> None:
    """Print the current cloud setup state (no secrets)."""
    st = tc.load_cloud_state()
    if not st:
        print("No cloud setup yet. Run `tenuo-admin setup`.")
        return
    cfg = tc.load_config()
    print("Cloud setup state:")
    for k in ("agent_id", "agent_name", "trigger_id", "service_account", "root"):
        v = st.get(k)
        if v:
            print(f"  {k:16}: {v[:24] + '…' if k == 'root' and len(v) > 24 else v}")
    if tc.has_approval_gates(cfg):
        cloud_cfg = cfg.get("cloud") or {}
        who = (st.get("web_fetch_approver") or cloud_cfg.get("approver_identity")
               or cloud_cfg.get("approver_identity_id") or "?")
        pid = st.get("session_approval_policy_id") or st.get("web_fetch_approval_policy_id")
        wired = pid or "NOT set up (run `tenuo-admin setup`)"
        gates = st.get("approval_gates") or [g[0] for g in tc.approval_entries(cfg)]
        print(f"  {'approval':16}: {', '.join(gates)} -> {who} | policy {wired}")


COMMANDS = {"setup": cmd_setup, "show": cmd_show}


def main() -> None:
    parser = argparse.ArgumentParser(prog=ADMIN_COMMAND, description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd")
    for name in COMMANDS:
        p = sub.add_parser(name)
        if name == "setup":
            p.add_argument(
                "--managed", action="store_true",
                help="mark this project org-managed: Cloud trigger is the sole authority "
                     "and local policy attenuates only (records managed=true in cloud state)")
    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return
    bind_project_paths(tc)
    COMMANDS[args.cmd](args)


if __name__ == "__main__":
    main()
