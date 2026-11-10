"""Policy reloads must reject ambiguous authority and invalid semantics."""
import json

import pytest
from tenuo_claude_code import cli


def load_policy(policy, bound, monkeypatch):
    policy.setdefault('allow_bundled', False)
    path = bound / 'tenuo.yaml'
    path.write_text(json.dumps(policy))
    monkeypatch.setattr(cli, 'CONFIG_FILE', path, raising=False)
    monkeypatch.setattr(cli, 'CLOUD_PROFILE', bound / 'no-cloud', raising=False)
    monkeypatch.setattr(cli, 'ADVANCED_PROFILE', bound / 'no-advanced', raising=False)
    return cli.load_config()


@pytest.mark.parametrize('allow', ['merge_pull_request', 'mcp__github__merge_pull_request'])
@pytest.mark.parametrize('cloud', [{}, {'trigger_id': 'trigger'}])
@pytest.mark.parametrize('key', ['allow', 'audit', 'audit_extra'])
def test_gated_mcp_cannot_be_restored_by_allow(allow, cloud, key, bound, monkeypatch):
    with pytest.raises(SystemExit, match='overlaps an approval-gated'):
        load_policy({key: [allow], 'cloud': cloud, 'mcp': {'server': 'github',
            'enforce': {'merge_pull_request': {'args': {'owner': 'exact:org'},
                                              'approval': {'threshold': 1}}}}}, bound, monkeypatch)


@pytest.mark.parametrize('allow', ['Bash', 'run_command'])
def test_native_gated_aliases_cannot_be_allowed(allow, bound, monkeypatch):
    with pytest.raises(SystemExit, match='overlaps an approval-gated'):
        load_policy({'allow': [allow], 'enforce': {'Bash': {'approval': {'threshold': 1}}}}, bound, monkeypatch)


@pytest.mark.parametrize('entry', [
    'unknown:value', {'args': {'value': 'unknown:value'}},
    {'approval': {'threshold': 1}, 'exempt': {'value': 'unknown:value'}},
    {'approval': {'threshold': 1, 'exempt': {'value': 'unknown:value'}}},
    {'approval': {'threshold': 1}, 'exempt': {'value': 123}},
    {'approval': {'threshold': 1}, 'exempt': 'pattern:*'},
    {'args': {'value': 'range:5'}},
])
def test_invalid_mcp_semantics_rejected(entry, bound, monkeypatch):
    with pytest.raises((SystemExit, ValueError)):
        load_policy({'mcp': {'enforce': {'echo': entry}}}, bound, monkeypatch)


@pytest.mark.parametrize('enforce', [
    {'Read': 'unknown:value'},
    {'Bash': {'approval': {'threshold': 1, 'exempt': 'unknown:value'}}},
    {'WebFetch': {'domains': ['example.com'], 'ports': [70000]}},
])
def test_native_semantics_validated_on_load(enforce, bound, monkeypatch):
    with pytest.raises((SystemExit, ValueError)):
        load_policy({'enforce': enforce}, bound, monkeypatch)


def test_distinct_mcp_allow_identity_does_not_overlap_gate(bound, monkeypatch):
    cfg = load_policy({"allow": ["mcp__prod-server__delete_deployment"],
        "mcp": {"server": "prod_server", "enforce": {
            "delete_deployment": {"approval": {"threshold": 1}}}}}, bound, monkeypatch)
    assert cli.audit_map(cfg) == {
        "mcp__prod-server__delete_deployment": "mcp__prod-server__delete_deployment"}
