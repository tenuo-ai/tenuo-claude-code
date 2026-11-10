"""Compile local policy to the Cloud trigger wire format without credentials or I/O."""
from __future__ import annotations
from . import policy
from .constraints import parse_range_spec, parse_ports
from .action_identity import REQUEST_FIELD, mcp_capability


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
        lo, hi = parse_range_spec(spec)
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
    ports = parse_ports(policy)
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
    gov = policy.governed_map(cfg)
    approval = policy.webfetch_approval(cfg)
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
        cap = mcp_capability(cfg, mtool)
        if cap in per_action:
            continue
        parsed = policy.parse_mcp_enforce_spec(raw)
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
            gated = list(exempt_args.keys()) or [policy.mcp_default_arg(mtool)]
            per_action[cap] = {a: {"_type": "wildcard"} for a in gated}
            gate_args: dict = {}
            for ek, es in exempt_args.items():
                gate_args[ek] = {"exempt": to_wire_constraint(es, sandbox)}
            approval_gates[cap] = {"args": gate_args or {a: {} for a in gated}}
    for constraints in per_action.values():
        constraints[REQUEST_FIELD] = {"_type": "wildcard"}
    # ALLOW capabilities (unconstrained): the hook routes allow-listed tools to
    # /verify/<cap>, so the warrant must GRANT them or every WebSearch/TodoWrite/…
    # is denied in enforce mode.
    for cap in policy.audit_map(cfg).values():
        per_action.setdefault(cap, {})
    # default: approve -> grant the catch-all cap WITH an approval gate, so any
    # tool not in enforce/allow pauses for human sign-off (Cloud-only; local
    # warrants never grant the catch-all, so local `approve` falls back to deny).
    # Needs a linked Cloud approval policy; without one we leave it ungranted (deny).
    if policy.default_mode(cfg) == "approve" and approval_policy_id:
        # Whole-tool gate (args: None) = tenuo-core's first-class "every invocation
        # requires approval", so every unlisted tool pauses for sign-off. The cap
        # wildcards `tool` (resolve_tool signs the tool name) purely so the approval's
        # request_hash binds per tool name — approving one unlisted tool must not
        # auto-approve another — not to make the gate fire.
        per_action.setdefault(policy.CATCHALL_AUDIT, {"tool": {"_type": "wildcard"}, REQUEST_FIELD: {"_type": "wildcard"}})
        approval_gates.setdefault(policy.CATCHALL_AUDIT, {"args": None})
    # Subagent spawn: a signed capability whose subagent_type is constrained to
    # the declared roles. Lets the runtime route the Agent/Task spawn through the
    # authorizer for a root-signed decision (instead of a local-only policy gate).
    roles = policy.subagent_roles(cfg)
    if roles:
        per_action["spawn_agent"] = {
            "subagent_type": {"_type": "one_of", "_value": list(roles.keys())}}
    wc = {
        "holder": "${event.agent_id}",
        "actions": sorted(per_action.keys()),
        "per_action_constraints": per_action,
        "ttl": policy.session_ttl_seconds(cfg),
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
