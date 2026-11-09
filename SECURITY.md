# Security

## Reporting vulnerabilities

Please **do not** open a public GitHub issue for security bugs.

Report privately via [GitHub Security Advisories](https://github.com/tenuo-ai/tenuo-claude-code/security/advisories/new).
Include steps to reproduce, affected versions, and impact if known.

We aim to acknowledge reports within a few business days.

## Scope

In scope: `tenuo-claude-code` (CLI, hooks, MCP proxy, authorizer integration),
default policy templates, and documented deployment patterns in this repo.

Out of scope: Tenuo Cloud control-plane bugs (report to Tenuo separately), Claude
Code itself, and `tenuo.yaml` policies you maintain locally.

## Secrets and the state directory

Never commit a legacy the state directory directory (keys, warrants, `cloud.env`) or real credentials. The demo
includes `demo/fake-secrets.env` with fake values for out-of-scope read tests.
Do not replace those values with real secrets.
