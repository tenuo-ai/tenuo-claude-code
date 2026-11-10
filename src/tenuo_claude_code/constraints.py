"""Constraint parsing shared by local warrants and Cloud compilation."""
from __future__ import annotations


def validate_webfetch_policy(cfg: dict) -> None:
    """Reject `enforce.WebFetch.approval` combined with `cidrs` (fail closed).

    Approval relaxes the host constraint to a wildcard and, for internal egress,
    turns off block_private — so a `cidrs:` allowlist meant to permit ONE private
    range would silently let EVERY private range reach the human gate, and the
    gate's domain-only exempt can't represent CIDR membership. The two mechanisms
    don't compose with today's url_safe primitives, so we refuse the combination
    rather than emit a policy that's wider than it reads. Enforced once in
    load_config, so local mint, Cloud build, and verify all see the same error.
    """
    wf = (cfg.get("enforce") or {}).get("WebFetch")
    if isinstance(wf, dict) and wf.get("approval") and wf.get("cidrs"):
        raise SystemExit(
            "enforce.WebFetch: `approval` cannot be combined with `cidrs`.\n"
            "  Approval wildcards the host and permits all private ranges to reach "
            "the gate, so the cidrs allowlist would not be enforced.\n"
            "  Use `domains:` with approval, or drop `approval` to hard-enforce cidrs.")


def _range_bound(text: str, spec: str):
    """Parse one side of a `range:min,max` bound; blank means open-ended (None)."""
    text = text.strip()
    if not text:
        return None
    try:
        return float(text) if ("." in text or "e" in text.lower()) else int(text)
    except ValueError:
        raise SystemExit(f"range bound '{text}' is not a number in '{spec}'.")


def parse_range_spec(spec: str) -> tuple:
    """Validate a `range:min,max` spec and return (lo, hi) bounds (None = open).

    Shared by local mint (make_constraint) and Cloud wire (admin.to_wire_constraint)
    so both reject the same specs. A blank side is open-ended, but not both (that
    is a match-all range), and a missing comma (`range:5`) is rejected outright —
    otherwise Cloud would silently emit `..` (match-all) or `5..` for inputs the
    local authorizer refuses.
    """
    _, _, rest = spec.partition(":")
    if "," not in rest:
        raise SystemExit(
            f"range constraint needs 'min,max' (either side may be blank) in '{spec}'.")
    lo, _, hi = rest.partition(",")
    lo_v, hi_v = _range_bound(lo, spec), _range_bound(hi, spec)
    if lo_v is None and hi_v is None:
        raise SystemExit(f"range constraint needs at least one bound in '{spec}'.")
    return lo_v, hi_v


def make_constraint(spec: str, sandbox: str):
    """Constraint DSL -> tenuo constraint object."""
    from tenuo import (Cidr, Exact, NotOneOf, OneOf, Pattern, Range, Regex,
                       Subpath, UrlPattern)
    from tenuo_core import Shlex  # core constraint type (mintable)

    spec = spec.replace("{sandbox}", sandbox)
    kind, _, rest = spec.partition(":")
    if kind == "subpath":
        return Subpath(rest)
    if kind == "shlex":
        return Shlex(allow=[v.strip() for v in rest.split(",") if v.strip()])
    if kind == "regex":
        return Regex(rest)
    if kind == "pattern":
        return Pattern(rest)
    if kind == "oneof":
        return OneOf([v.strip() for v in rest.split(",")])
    if kind == "notoneof":
        return NotOneOf([v.strip() for v in rest.split(",")])
    if kind == "exact":
        return Exact(rest)
    if kind == "urlpattern":
        return UrlPattern(rest)
    if kind == "cidr":
        # Any tool argument that is an IP/host (not just WebFetch): the value
        # must fall inside the CIDR block. Non-IP values fail closed.
        return Cidr(rest)
    if kind == "range":
        return Range(*parse_range_spec(spec))
    raise SystemExit(
        f"Unknown constraint kind '{kind}' in '{spec}'. "
        "Valid kinds: subpath, shlex, regex, pattern, oneof, notoneof, exact, "
        "range, urlpattern, cidr (or a WebFetch policy with domains/cidrs). "
        "Syntax: <kind>:<value>, e.g. subpath:{sandbox} or cidr:10.0.0.0/8.")


def parse_ports(policy: dict) -> list[int] | None:
    """Validate a WebFetch `ports:` allowlist -> list[int], or None when unset.

    Shared by local mint (make_web_constraints) and Cloud wire
    (admin.url_safe_ssrf_wire) so a malformed entry fails with one clear policy
    error on both paths instead of a Python traceback. Ports are u16 in core.
    """
    raw = policy.get("ports")
    if not raw:
        return None
    out: list[int] = []
    for p in raw:
        try:
            n = int(p)
        except (TypeError, ValueError):
            raise SystemExit(f"tenuo.yaml WebFetch `ports:` must be integers, got {p!r}")
        if not 1 <= n <= 65535:
            raise SystemExit(f"tenuo.yaml WebFetch `ports:` value {n} out of range (1-65535)")
        out.append(n)
    return out


def make_web_constraints(policy: dict, *, approval_gate: bool = False) -> dict:
    """Org egress policy -> {url: UrlSafe, host: AnyOf(domains|cidrs) or Wildcard}.

    approval_gate=True: SSRF-only url + wildcard host; domain policy moves to Cloud gate.
    """
    from tenuo_core import AnyOf, Cidr, Pattern, UrlSafe, Wildcard

    domains = [str(d) for d in policy.get("domains") or []]
    cidrs = [str(c) for c in policy.get("cidrs") or []]
    if not domains and not cidrs:
        raise SystemExit("WebFetch policy needs at least one of: domains, cidrs")
    # https-only unless internal ranges are in play (internal services are
    # often plain http); explicit `schemes:` in the policy overrides.
    schemes = [str(s) for s in policy.get("schemes") or
               (["https"] if not cidrs else ["http", "https"])]
    kwargs = dict(allow_schemes=schemes,
                  block_private=not cidrs, block_loopback=True,
                  block_metadata=True, block_reserved=True)
    ports = parse_ports(policy)
    if ports:
        kwargs["allow_ports"] = ports
    url = UrlSafe(**kwargs)
    if approval_gate:
        return {"url": url, "host": Wildcard()}
    members = [Pattern(d) for d in domains] + [Cidr(c) for c in cidrs]
    host = members[0] if len(members) == 1 else AnyOf(members)
    return {"url": url, "host": host}
