"""mcp_proxy_decision — how the MCP proxy turns an authorize result into an action.

Pure logic, no Docker / authorizer / network (per conftest). This is the decision
the proxy's call_tool handler makes AFTER authorize_call returns — including the
human-in-the-loop case, where authorize_call has already blocked on the Cloud
approval poll and `allowed` reflects the approver's decision. See
writing/hitl-mcp-gateway-plan.md.
"""
from __future__ import annotations

from tenuo_claude_code import cli
import pytest


def test_allow_forwards(cli_mod):
    forward, message = cli_mod.mcp_proxy_decision(True, "authorized", False, "read_file")
    assert forward is True
    assert message is None


def test_hard_deny_does_not_forward(cli_mod):
    forward, message = cli_mod.mcp_proxy_decision(
        False, "not permitted by policy", False, "delete_deployment")
    assert forward is False
    assert message == "Tenuo denied delete_deployment: not permitted by policy"


def test_approval_pending_is_distinct_from_hard_deny(cli_mod):
    # authorize_with_approval surfaces the pending/declined/timed-out family with
    # APPROVAL_PENDING_REASON ("approval required") in the reason. The agent must be
    # able to tell "not run, awaiting/declined approval" from "denied by policy".
    for areason in (
        f"{cli_mod.APPROVAL_PENDING_REASON}: 1 approval(s) required",
        f"{cli_mod.APPROVAL_PENDING_REASON} — approval timed out (no response from approver)",
        f"{cli_mod.APPROVAL_PENDING_REASON} — denied by approver (no reason given)",
    ):
        forward, message = cli_mod.mcp_proxy_decision(False, areason, False, "delete_deployment")
        assert forward is False
        assert message == f"Tenuo: delete_deployment not run — {areason}"
        assert "denied delete_deployment" not in message  # not framed as a hard deny


def test_audit_mode_always_forwards(cli_mod):
    # Observe-only: even a would-deny forwards (the caller logs WOULD-DENY).
    forward, message = cli_mod.mcp_proxy_decision(False, "not permitted by policy", True, "delete_deployment")
    assert forward is True
    assert message is None


def test_audit_mode_forwards_even_on_approval_pending(cli_mod):
    forward, message = cli_mod.mcp_proxy_decision(
        False, f"{cli_mod.APPROVAL_PENDING_REASON}: 1 approval(s) required", True, "delete_deployment")
    assert forward is True
    assert message is None


def test_downstream_script_path_runs_with_this_python(cli_mod, bound):
    import sys

    command, args, env, label = cli_mod.downstream_server({"downstream": "server.py"})
    assert command == sys.executable
    assert args == [str((bound / "server.py").resolve())] and env is None and label == args[0]


def test_downstream_command_with_env_from_proxy_environment(cli_mod, bound, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t0ken")
    command, args, env, label = cli_mod.downstream_server({"downstream": {
        "command": "docker",
        "args": ["run", "-i", "--rm", "ghcr.io/github/github-mcp-server"],
        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}", "UNSET": "${NOT_SET_ANYWHERE}"},
    }})
    assert (command, args[-1]) == ("docker", "ghcr.io/github/github-mcp-server")
    assert env == {"GITHUB_PERSONAL_ACCESS_TOKEN": "t0ken", "UNSET": "${NOT_SET_ANYWHERE}"}
    assert label == "docker run -i --rm ghcr.io/github/github-mcp-server"


@pytest.mark.parametrize("spec", [
    None, "", {"args": ["x"]}, {"command": "npx", "args": "x"}, {"command": "npx", "env": {"A": 1}},
])
def test_downstream_rejects_bad_shapes(cli_mod, bound, spec):
    with pytest.raises(SystemExit):
        cli_mod.downstream_server({"downstream": spec})


def test_stdio_proxy_preserves_results_and_denies_from_an_external_cwd(tmp_path):
    """Exercise real MCP framing, downstream cwd, and error/structured results."""
    import asyncio
    import json
    import sys
    from pathlib import Path
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    project = tmp_path / "project"
    project.mkdir()
    (project / "server.py").write_text('''from mcp.server.fastmcp import FastMCP
server = FastMCP("review-test")
@server.tool()
def echo(value: str) -> dict[str, str]:
    if value == "error":
        raise ValueError("downstream failure")
    return {"value": value}
server.run(transport="stdio")
''')
    (project / "tenuo.yaml").write_text(json.dumps({
        "name": "proxy-test", "mode": "enforce", "default": "deny",
        "mcp": {"downstream": {"command": sys.executable, "args": ["server.py"]},
                "enforce": {"echo": {"arg": "value", "constraint": "pattern:*"}}},
    }))
    # Stub only the authorization service; both MCP transports are real processes.
    launcher = '''from tenuo_claude_code import cli, paths
paths.bind_project_paths(cli)
cli.authorize_call = lambda cfg, name, tin, *a, **kw: (tin.get("value") != "deny", "test decision", True, name, {})
cli.write_receipt = lambda row: True
cli.cmd_mcp_proxy(None)
'''

    async def exercise():
        params = StdioServerParameters(command=sys.executable, args=["-c", launcher],
            cwd=str(tmp_path), env={"TENUO_PROJECT_DIR": str(project),
                "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
                "HOME": str(tmp_path)})
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                assert [t.name for t in (await client.list_tools()).tools] == ["echo"]
                ok = await client.call_tool("echo", {"value": "ok"})
                assert not ok.isError and ok.structuredContent == {"value": "ok"}
                failed = await client.call_tool("echo", {"value": "error"})
                assert failed.isError and "downstream failure" in failed.content[0].text
                denied = await client.call_tool("echo", {"value": "deny"})
                assert denied.isError and "test decision" in denied.content[0].text
                policy = json.loads((project / "tenuo.yaml").read_text())
                policy["mode"] = "dry-run"
                (project / "tenuo.yaml").write_text(json.dumps(policy))
                assert not (await client.call_tool("echo", {"value": "deny"})).isError
                policy["mode"] = "enforce"
                (project / "tenuo.yaml").write_text(json.dumps(policy))
                assert (await client.call_tool("echo", {"value": "deny"})).isError
                # Valid YAML with invalid semantics must also fail before authorization.
                for replacement in [
                    {"arg": "value", "constraint": "unknown:value"},
                    {"approval": {"threshold": 1}, "exempt": {"value": "unknown:value"}},
                ]:
                    policy["mcp"]["enforce"]["echo"] = replacement
                    (project / "tenuo.yaml").write_text(json.dumps(policy))
                    invalid = await client.call_tool("echo", {"value": "ok"})
                    assert invalid.isError and "policy unavailable" in invalid.content[0].text
                policy["mcp"]["enforce"]["echo"] = {"arg": "value", "constraint": "pattern:*"}
                # A broken replacement policy must never retain the old permissive snapshot.
                (project / "tenuo.yaml").write_text("[invalid")
                assert (await client.call_tool("echo", {"value": "ok"})).isError
                policy["mcp"]["downstream"]["args"] = ["replacement.py"]
                (project / "tenuo.yaml").write_text(json.dumps(policy))
                changed = await client.call_tool("echo", {"value": "ok"})
                assert changed.isError and "reconnect" in changed.content[0].text

    asyncio.run(exercise())
