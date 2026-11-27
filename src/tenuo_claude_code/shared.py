"""Use MCP servers that someone shared with you, from Claude Code.

    tenuo-claude accept 'https://host:8765/#HG-XXXX-XXXX'

Pairs this machine with the owner's server, waits for the owner to approve, and
adds one MCP server to Claude Code. Calls from Claude go through
``tenuo-claude shared run NAME``, which signs each one with this machine's key
and the owner's latest warrant.

Nothing else changes: no hooks, no policy, no authorizer. Claude Code's other
tools and projects work as before.

Each shared server keeps its own folder under ``~/.tenuo/shared/NAME``: a key that
never leaves this machine (0600) and ``server.json`` (address, this key's public half,
and the owner's public key pinned at approval).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

STORE = Path(os.environ.get("TENUO_SHARED_HOME", Path.home() / ".tenuo" / "shared"))
WARRANT_CACHE_SECONDS = 5


class SharedError(Exception):
    """A problem to show the user as is."""


# --- storage ------------------------------------------------------------------------
def _b64(data: bytes) -> str:
    return base64.b64encode(bytes(data)).decode()


def fingerprint(public_key_bytes: bytes) -> str:
    digest = hashlib.sha256(bytes(public_key_bytes)).hexdigest()[:8]
    return f"{digest[:4]}-{digest[4:]}"


def _private_dirs(path: Path) -> None:
    """Create path's folders, keeping the store and everything under it to this user."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    for folder in (STORE, *[p for p in path.parents if STORE in p.parents]):
        if folder.is_dir():
            os.chmod(folder, 0o700)


def _write_private(path: Path, data: bytes) -> None:
    _private_dirs(path)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _load_key(folder: Path, create: bool = False):
    from tenuo import SigningKey

    path = folder / "key"
    if path.exists():
        return SigningKey.from_bytes(base64.b64decode(path.read_text().strip(), validate=True))
    if not create:
        raise SharedError(f"This machine's key for {folder.name} is missing. Ask the owner for a new invitation.")
    key = SigningKey.generate()
    _write_private(path, _b64(key.secret_key_bytes()).encode())
    return key


def load(name: str) -> dict:
    try:
        return json.loads((STORE / name / "server.json").read_text())
    except FileNotFoundError:
        raise SharedError(f"Nothing called {name!r} has been shared with you here. "
                          "Run `tenuo-claude shared list` to see what has.") from None


def save(name: str, state: dict) -> None:
    _write_private(STORE / name / "server.json", json.dumps(state, indent=2).encode())


def names() -> list[str]:
    if not STORE.is_dir():
        return []
    return sorted(p.name for p in STORE.iterdir() if (p / "server.json").exists())


# --- talking to the owner's server ----------------------------------------------------
def parse_link(link: str) -> tuple[str, str]:
    parts = urlsplit(link.strip().strip("'\""))
    if parts.scheme not in ("http", "https") or not parts.netloc or not parts.fragment:
        raise SharedError("That doesn't look like a whole invitation link. It starts with http "
                          "and ends with #HG-…; paste all of it, in quotes.")
    return f"{parts.scheme}://{parts.netloc}", parts.fragment


def _http(method: str, url: str, **kw):
    import httpx

    try:
        return httpx.request(method, url, timeout=10, **kw)
    except httpx.HTTPError:
        host = urlsplit(url).netloc
        raise SharedError(f"Couldn't reach {host}. Check you're on a network that can reach it and "
                          "that the owner's server is running.") from None


def fetch(server: str, holder: str) -> dict:
    r = _http("GET", f"{server}/tenuo/warrant", params={"holder": holder})
    try:
        return r.json()
    except ValueError:
        raise SharedError(f"{urlsplit(server).netloc} didn't answer like a shared server.") from None


def suggest_name(server: str, offered: str | None) -> str:
    base = offered or urlsplit(server).hostname or "shared"
    name = re.sub(r"[^a-z0-9-]+", "-", base.lower()).strip("-") or "shared"
    taken, candidate, n = set(names()), name, 2
    while candidate in taken:
        candidate, n = f"{name}-{n}", n + 1
    return candidate


def pair(link: str, person: str, agent: str, out=print) -> tuple[str, dict]:
    """Send this machine's new public key with the invitation code. Returns (folder name, state)."""
    server, code = parse_link(link)
    pending = STORE / ".pending" / hashlib.sha256(code.encode()).hexdigest()[:12]
    key = _load_key(pending, create=True)
    holder = _b64(key.public_key_bytes())
    out(f"✓ Created a key for this computer (fingerprint {fingerprint(key.public_key_bytes())})")
    r = _http("POST", f"{server}/tenuo/pair",
              json={"code": code, "public_key": holder, "person": person, "agent": agent})
    if r.status_code != 202:
        try:
            message = r.json().get("error")
        except ValueError:
            message = None
        raise SharedError(message or f"The server refused the invitation ({r.status_code}).")
    out(f"✓ Sent it to {urlsplit(server).netloc}")
    return pending.name, {"server": server, "holder": holder, "pending": pending.name}


def wait_for_approval(state: dict, seconds: float, out=print) -> dict | None:
    deadline = time.time() + seconds
    while True:
        body = fetch(state["server"], state["holder"])
        status = body.get("status")
        if status == "approved":
            return body
        if status in ("declined", "ended"):
            raise SharedError("The owner declined this request.")
        if time.time() >= deadline:
            return None
        time.sleep(1)


def describe(warrant) -> str:
    from datetime import datetime

    value = warrant.expires_at()
    when = (datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str)
            else datetime.fromtimestamp(value))
    return f"{', '.join(sorted(warrant.tools))} until {when.astimezone().strftime('%a %H:%M %Z')}"


def finish(state: dict, body: dict) -> tuple[str, dict]:
    """Pin the owner's key and move the pending folder to its final name."""
    name = suggest_name(state["server"], body.get("name"))
    pending = STORE / ".pending" / state.pop("pending")
    (STORE / name).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.replace(pending, STORE / name)
    state.update(issuer=body["issuer"], name=name)
    save(name, state)
    return name, state


# --- Claude Code registration ---------------------------------------------------------
def runner_command(name: str) -> list[str]:
    """The command Claude Code runs: this install's tenuo-claude, by absolute path."""
    me = Path(sys.argv[0])
    if me.name in ("tenuo-claude", "tenuo-claude-code") and me.exists():
        exe = [str(me.resolve())]
    elif shutil.which("tenuo-claude"):
        exe = [shutil.which("tenuo-claude")]
    else:
        exe = [sys.executable, "-m", "tenuo_claude_code.cli"]
    return [*exe, "shared", "run", name]


def claude_add_command(name: str, scope: str) -> list[str]:
    env = ["-e", f"TENUO_SHARED_HOME={STORE}"] if "TENUO_SHARED_HOME" in os.environ else []
    return ["claude", "mcp", "add", "--scope", scope, name, *env, "--", *runner_command(name)]


def add_to_claude(name: str, scope: str) -> bool:
    if not shutil.which("claude"):
        return False
    result = subprocess.run(claude_add_command(name, scope), capture_output=True, text=True, check=False)
    return result.returncode == 0


def remove_from_claude(name: str) -> None:
    if shutil.which("claude"):
        for scope in ("user", "local", "project"):
            subprocess.run(["claude", "mcp", "remove", "--scope", scope, name], capture_output=True, check=False)


# --- the stdio MCP server Claude Code runs ---------------------------------------------
def refusal(text: str):
    from mcp.types import CallToolResult, TextContent

    return CallToolResult(content=[TextContent(type="text", text=text)], isError=True)


def serve(name: str) -> None:
    """Serve the owner's tools to Claude Code over stdio, signing each call."""
    import asyncio

    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import CallToolResult
    from tenuo import PublicKey, Warrant, configure, key_scope, warrant_scope
    from tenuo.mcp import SecureMCPClient

    state = load(name)
    key = _load_key(STORE / name)
    configure(issuer_key=key, trusted_roots=[PublicKey.from_bytes(base64.b64decode(state["issuer"]))])
    cache: dict = {"at": 0.0, "body": None}

    def current() -> tuple[object | None, str | None]:
        """The latest warrant, or a plain reason there isn't one."""
        if time.time() - cache["at"] > WARRANT_CACHE_SECONDS:
            cache.update(at=time.time(), body=fetch(state["server"], state["holder"]))
        body = cache["body"]
        if body.get("issuer") and body["issuer"] != state["issuer"]:
            return None, "This server's owner key changed since you paired, so Tenuo won't call it."
        status = body.get("status")
        if status == "ended":
            return None, "The owner ended this access."
        if status != "approved":
            return None, f"This access isn't active ({status})."
        return Warrant.from_base64(body["warrant"]), None

    async def run():
        async with SecureMCPClient(url=f"{state['server']}/mcp", transport="http", inject_warrant=True) as up:
            proxy = Server(f"tenuo-shared-{name}")

            @proxy.list_tools()
            async def _list():
                warrant, _ = await asyncio.to_thread(current)
                allowed = set(warrant.tools) if warrant else set()
                # Show Claude only what this access covers. Results come back as content,
                # so drop output schemas rather than claim structured output we don't relay.
                return [t.model_copy(update={"outputSchema": None})
                        for t in await up.get_tools() if t.name in allowed]

            @proxy.call_tool()
            async def _call(tool: str, arguments: dict):
                try:
                    warrant, reason = await asyncio.to_thread(current)
                except SharedError as exc:
                    return refusal(str(exc))
                if warrant is None:
                    return refusal(reason)
                if tool not in warrant.tools:
                    return refusal(f"Your access doesn't include {tool}. You can use "
                                   f"{', '.join(sorted(warrant.tools))}. Ask the owner if you need more.")
                with warrant_scope(warrant), key_scope(key):
                    try:
                        content = await up.call_tool(tool, dict(arguments or {}))
                    except Exception as exc:  # noqa: BLE001 - any failure becomes a plain refusal for Claude
                        return refusal(f"Not allowed: {str(exc).splitlines()[0]}")
                return CallToolResult(content=list(content or []), isError=False)

            async with stdio_server() as (r, w):
                await proxy.run(r, w, proxy.create_initialization_options())

    asyncio.run(run())


# --- commands --------------------------------------------------------------------------
def cmd_accept(args) -> int:
    try:
        _server, code = parse_link(args.link)
        folder = hashlib.sha256(code.encode()).hexdigest()[:12]
        saved = STORE / ".pending" / folder / "state.json"
        if saved.exists():  # running the same command again resumes the wait
            state = json.loads(saved.read_text())
        else:
            folder, state = pair(args.link, args.person, args.agent)
        print(f"… Waiting for the owner to approve. Tell them your key is "
              f"{fingerprint(base64.b64decode(state['holder']))}.")
        body = wait_for_approval(state, args.wait)
        if body is None:
            _write_private(STORE / ".pending" / folder / "state.json", json.dumps(state).encode())
            print("Still waiting. Run the same command again later to check.")
            return 1
        name, state = finish(state, body)
        from tenuo import Warrant

        print(f"✓ Approved: {describe(Warrant.from_base64(body['warrant']))}")
    except SharedError as exc:
        print(f"✗ {exc}")
        return 2

    command = " ".join(claude_add_command(name, args.scope))
    if args.no_claude:
        print(f"\nTo use it in Claude Code, run:\n  {command}")
        return 0
    if not shutil.which("claude"):
        print(f"\nClaude Code's `claude` command isn't on your PATH. When it is, run:\n  {command}")
        return 0
    where = "all your projects" if args.scope == "user" else "this project"
    if not args.yes:
        answer = input(f"\nAdd {name!r} to Claude Code for {where}? Nothing else in Claude changes. [Y/n] ")
        if answer.strip().lower() in ("n", "no"):
            print(f"Not added. To add it later:\n  {command}")
            return 0
    if add_to_claude(name, args.scope):
        print(f"✓ Added {name!r} to Claude Code. Start a new Claude Code session and ask it to use {name}.")
    else:
        print(f"✗ Claude Code didn't accept the change. Run it yourself:\n  {command}")
    return 0


def cmd_shared(args) -> int:
    try:
        if args.shared_cmd == "run":
            serve(args.name)
            return 0
        if args.shared_cmd == "remove":
            load(args.name)
            remove_from_claude(args.name)
            shutil.rmtree(STORE / args.name)
            print(f"✓ Removed {args.name!r} from Claude Code and deleted this machine's key for it.")
            return 0
        # list
        from tenuo import Warrant

        shown = names()
        if not shown:
            print("Nothing has been shared with you on this machine yet.")
            return 0
        for name in shown:
            state = load(name)
            try:
                body = fetch(state["server"], state["holder"])
                status = body.get("status")
                detail = describe(Warrant.from_base64(body["warrant"])) if status == "approved" else status
            except SharedError:
                detail = "server unreachable"
            print(f"{name:<16} {urlsplit(state['server']).netloc:<24} {detail}")
        return 0
    except SharedError as exc:
        print(f"✗ {exc}", file=sys.stderr if args.shared_cmd == "run" else sys.stdout)
        return 2


def add_parsers(sub) -> None:
    pa = sub.add_parser("accept", help="use an MCP server someone shared with you (one invitation link)")
    pa.add_argument("link", help="the invitation link you were sent")
    pa.add_argument("--as", dest="person", default=os.environ.get("USER", "guest"),
                    help="your name, shown to the owner")
    pa.add_argument("--agent", default="Claude Code", help="shown to the owner")
    pa.add_argument("--scope", choices=("user", "local", "project"), default="user",
                    help="where Claude Code adds the server (default: all your projects)")
    pa.add_argument("--wait", type=float, default=600, help="seconds to wait for approval")
    pa.add_argument("--yes", action="store_true", help="add to Claude Code without asking")
    pa.add_argument("--no-claude", action="store_true", help="don't change Claude Code; print the command")
    ps = sub.add_parser("shared", help="list or remove what has been shared with you")
    pss = ps.add_subparsers(dest="shared_cmd", required=True)
    pss.add_parser("list", help="what has been shared with you, and until when")
    pr = pss.add_parser("remove", help="remove a shared server and this machine's key for it")
    pr.add_argument("name")
    prun = pss.add_parser("run", help=argparse_suppress())
    prun.add_argument("name")


def argparse_suppress():
    import argparse

    return argparse.SUPPRESS
