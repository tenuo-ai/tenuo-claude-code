# Contributing

Apache-2.0. See [LICENSE](LICENSE). Bug reports and PRs welcome.

## Getting started

```bash
git clone https://github.com/tenuo-ai/tenuo-claude-code.git
cd tenuo-claude-code
uv venv && uv sync && chmod +x bin/tenuo-claude
cd demo && uv run tenuo-claude verify   # reference project with sample tenuo.yaml
```

Project discovery: `tenuo.yaml` in cwd or any parent, or set `TENUO_PROJECT_DIR`.
Re-run `init` or `refresh` after switching Python venvs (hooks pin `sys.executable`).

## Pull requests

1. Fork and branch from `main`.
2. Keep changes focused; match existing style in `src/tenuo_claude_code/`.
3. Run `uv run --with pytest pytest` (fast unit tests, no Docker). If you touch enforcement
   or policy wiring, also run `cd demo && tenuo-claude verify` (live authorizer).
4. Do not commit `.state/`, real API keys, or home-directory paths.

Security issues: see [SECURITY.md](SECURITY.md). No public issues for vulnerabilities.

## Never commit secrets

| Path | Contains |
|------|----------|
| `.state/` | Holder/issuer keys, warrant, receipts, `cloud.env` |
| `.claude/settings.json` | Generated hook wiring |
| `~/.tenuo/admin.env` | Admin key for `tenuo-admin setup` only |

Safe to commit: source, `demo/` (sample policy and `fake-secrets.env` decoys),
examples, and templates (`*.example`).

Before pushing, scan staged diffs for bearer tokens (`tc_…`, `tenuo_ct_…`) and paths
under `/Users/` or `C:\`.

## Code layout

| Module | Role |
|--------|------|
| `src/tenuo_claude_code/cli.py` | Policy, hooks, MCP proxy, lifecycle commands |
| `src/tenuo_claude_code/admin.py` | One-time Cloud setup (`tenuo-admin`) |
| `src/tenuo_claude_code/verify.py` | Policy-driven authorizer self-test |
| `src/tenuo_claude_code/data/harness_tools.yaml` | Bundled audit-allow tool list |
| `plugins/tenuo/` | Claude Code plugin (hooks, launcher, `/tenuo:*` skills); decision table tested in `tests/test_plugin_launcher.py` |
| `.claude-plugin/marketplace.json` | Marketplace entry so `/plugin marketplace add` works on this repo |

Root `scripts/tenuo_claude.py` / `scripts/tenuo_admin.py` are thin shims; prefer `tenuo-claude` on PATH.

When Claude Code adds new inert harness tools, append them to
`src/tenuo_claude_code/data/harness_tools.yaml` and run `verify`.

## Releases (maintainers)

PyPI package: **`tenuo-claude-code`**. Tag `v*` triggers
[`.github/workflows/release.yml`](.github/workflows/release.yml) (trusted publishing
or `PYPI_TOKEN` secret).

Release steps:

1. Bump `version` in `pyproject.toml`, `src/tenuo_claude_code/__init__.py`, and `uv.lock`.
   If anything under `plugins/tenuo/` changed, also bump `version` in
   `plugins/tenuo/.claude-plugin/plugin.json` (installed plugins only update when it changes)
   and run `claude plugin validate . --strict` and `claude plugin validate plugins/tenuo --strict`.
2. Commit (`Release X.Y.Z`) and push the `vX.Y.Z` tag (this triggers the PyPI publish).
3. Always publish brief release notes:
   `gh release create vX.Y.Z --verify-tag --title vX.Y.Z --notes "<one short paragraph or a few bullets>"`.

## Policy templates

Illustrative `tenuo.yaml` patterns for tool users live in
[examples/policies/](examples/policies/). PRs welcome for new **use-case** templates
(generic names, no org hostnames or secrets). See that README for contribution rules.

Users install `tenuo-claude-code`, save an adapted template as `tenuo.yaml` in their
project directory, and run `tenuo-claude init` from there.

## Reference demo

Sample policy, sandbox, and scripted tour: [demo/](demo/).
