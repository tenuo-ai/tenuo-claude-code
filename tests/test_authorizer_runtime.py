"""Unit tests for authorizer backend selection and binary discovery."""

from __future__ import annotations

import argparse
import ssl
from pathlib import Path
from unittest import mock

import certifi
import pytest

from tenuo_claude_code import authorizer_runtime as art


def test_authorizer_crate_version():
    # A real pre-release identifier is preserved.
    assert art.authorizer_crate_version("tenuo/authorizer:0.1.0-beta.24") == "0.1.0-beta.24"
    # Docker can't put '+' in a tag, so `+authz.N` build metadata is rendered as
    # `-authz.N`; the crate version drops it (matching the binary's /status report).
    assert art.authorizer_crate_version("tenuo/authorizer:0.2.0-authz.2") == "0.2.0"
    assert art.version_compatible("0.2.0+authz.2",
                                  art.authorizer_crate_version("tenuo/authorizer:0.2.0-authz.2"))


def test_install_hint():
    assert art.install_hint() == "run: tenuo-claude install-authorizer"


def test_parse_binary_version():
    assert art.parse_binary_version("Tenuo Authorizer v0.1.0-beta.24+authz.1\n") == "0.1.0-beta.24+authz.1"
    assert art.crate_version_from_authorizer_version("0.1.0-beta.24+authz.1") == "0.1.0-beta.24"


def test_version_compatible():
    assert art.version_compatible("0.1.0-beta.24+authz.1", "0.1.0-beta.24")
    assert not art.version_compatible("0.1.0-beta.23+authz.1", "0.1.0-beta.24")


def test_resolve_authorizer_port_default(monkeypatch):
    monkeypatch.delenv(art.AUTHORIZER_PORT_ENV, raising=False)
    monkeypatch.delenv(art.LEGACY_AUTHORIZER_PORT_ENV, raising=False)
    assert art.resolve_authorizer_port() == art.DEFAULT_AUTHORIZER_PORT


def test_resolve_authorizer_port_tenuo_env(monkeypatch):
    monkeypatch.setenv(art.AUTHORIZER_PORT_ENV, "9091")
    monkeypatch.setenv(art.LEGACY_AUTHORIZER_PORT_ENV, "3000")
    assert art.resolve_authorizer_port() == 9091


def test_resolve_authorizer_port_legacy_fallback(monkeypatch):
    monkeypatch.delenv(art.AUTHORIZER_PORT_ENV, raising=False)
    monkeypatch.setenv(art.LEGACY_AUTHORIZER_PORT_ENV, "9092")
    assert art.resolve_authorizer_port() == 9092


def test_choose_backend_flags():
    args = argparse.Namespace(native=True, docker=False)
    assert art.choose_backend(args) == "native"
    args = argparse.Namespace(native=False, docker=True)
    assert art.choose_backend(args) == "docker"


def test_choose_backend_env_native(monkeypatch):
    monkeypatch.setenv("TENUO_AUTHORIZER_NATIVE", "1")
    args = argparse.Namespace(native=False, docker=False)
    with mock.patch.object(art, "docker_ok", return_value=(True, "ok")):
        assert art.choose_backend(args) == "native"


def test_choose_backend_auto_fallback(monkeypatch):
    monkeypatch.delenv("TENUO_AUTHORIZER_NATIVE", raising=False)
    monkeypatch.delenv("TENUO_AUTHORIZER_BACKEND", raising=False)
    args = argparse.Namespace(native=False, docker=False)
    with mock.patch.object(art, "docker_ok", return_value=(False, "not installed")):
        assert art.choose_backend(args) == "native"
    with mock.patch.object(art, "docker_ok", return_value=(True, "ok")):
        assert art.choose_backend(args) == "docker"


def test_resolve_binary_env_override(tmp_path, monkeypatch):
    binary = tmp_path / "tenuo-authorizer"
    binary.write_bytes(b"fake")
    monkeypatch.setenv("TENUO_AUTHORIZER_BIN", str(binary))
    assert art.resolve_authorizer_binary() == binary


def test_resolve_binary_on_path(tmp_path, monkeypatch):
    monkeypatch.delenv("TENUO_AUTHORIZER_BIN", raising=False)
    binary = tmp_path / "tenuo-authorizer"
    binary.write_bytes(b"fake")
    with mock.patch.object(art, "managed_binary_path", return_value=tmp_path / "missing"):
        with mock.patch("shutil.which", return_value=str(binary)):
            assert art.resolve_authorizer_binary() == binary


def test_resolve_binary_missing(monkeypatch):
    monkeypatch.delenv("TENUO_AUTHORIZER_BIN", raising=False)
    with mock.patch("shutil.which", return_value=None):
        with mock.patch.object(art, "managed_binary_path") as mp:
            mp.return_value = Path("/nonexistent/tenuo-authorizer")
            with pytest.raises(SystemExit, match="install-authorizer"):
                art.resolve_authorizer_binary()


def test_find_authorizer_binary_managed(tmp_path, monkeypatch):
    monkeypatch.delenv("TENUO_AUTHORIZER_BIN", raising=False)
    managed = tmp_path / "bin" / "tenuo-authorizer"
    managed.parent.mkdir()
    managed.write_bytes(b"fake")
    with mock.patch.object(art, "managed_binary_path", return_value=managed):
        with mock.patch("shutil.which", return_value=None):
            assert art.find_authorizer_binary() == managed


def test_install_authorizer_skips_when_current(tmp_path, monkeypatch):
    managed = tmp_path / "bin" / "tenuo-authorizer"
    managed.parent.mkdir()
    managed.write_bytes(b"fake")
    with mock.patch.object(art, "managed_binary_path", return_value=managed):
        with mock.patch.object(art, "query_binary_version", return_value="0.3.0+authz.3"):
            with mock.patch.object(art, "download_release_binary") as dl:
                result = art.install_authorizer(force=False)
                assert result == managed
                dl.assert_not_called()


def test_runtime_meta_roundtrip(tmp_path):
    art.write_runtime_meta(tmp_path, backend="native", binary="/usr/bin/tenuo-authorizer")
    assert art.read_runtime_backend(tmp_path) == "native"
    assert art.read_runtime_meta(tmp_path)["binary"] == "/usr/bin/tenuo-authorizer"
    art.clear_runtime_meta(tmp_path)
    assert art.read_runtime_backend(tmp_path) is None


def test_find_authorizer_binary_none(monkeypatch):
    monkeypatch.delenv("TENUO_AUTHORIZER_BIN", raising=False)
    with mock.patch.object(art, "managed_binary_path", return_value=Path("/nonexistent/tenuo-authorizer")):
        with mock.patch("shutil.which", return_value=None):
            assert art.find_authorizer_binary() is None


def test_assert_port_available_free(monkeypatch, tmp_path):
    with mock.patch.object(art, "port_listening", return_value=False):
        art.assert_port_available(9090, "http://127.0.0.1:9090", tmp_path)


def test_assert_port_available_foreign(monkeypatch, tmp_path):
    with mock.patch.object(art, "port_listening", return_value=True):
        with mock.patch.object(art, "is_tenuo_authorizer_health", return_value=False):
            with pytest.raises(SystemExit, match="already in use"):
                art.assert_port_available(9090, "http://127.0.0.1:9090", tmp_path)


def test_ensure_binary_version_mismatch(tmp_path, monkeypatch):
    binary = tmp_path / "tenuo-authorizer"
    binary.write_bytes(b"fake")
    monkeypatch.delenv("TENUO_AUTHORIZER_SKIP_VERSION", raising=False)
    with mock.patch.object(art, "query_binary_version", return_value="0.1.0-beta.23+authz.1"):
        with pytest.raises(SystemExit, match="does not match pinned"):
            art.ensure_binary_version(binary)


def test_ensure_binary_version_skip_env(tmp_path, monkeypatch):
    binary = tmp_path / "tenuo-authorizer"
    binary.write_bytes(b"fake")
    monkeypatch.setenv("TENUO_AUTHORIZER_SKIP_VERSION", "1")
    with mock.patch.object(art, "query_binary_version", return_value="0.1.0-beta.23+authz.1"):
        assert art.ensure_binary_version(binary) == "0.1.0-beta.23+authz.1"


def test_install_authorizer_cmd_without_project(tmp_path, monkeypatch):
    import sys
    from pathlib import Path

    from tenuo_claude_code import cli

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["tenuo-claude", "install-authorizer"])
    fake = tmp_path / "bin" / "tenuo-authorizer"
    fake.parent.mkdir()
    fake.write_bytes(b"fake")
    monkeypatch.setattr(art, "install_authorizer", lambda *a, **kw: fake)
    monkeypatch.setattr(art, "query_binary_version", lambda p: "0.3.0+authz.3")
    cli.main()


def test_ssl_context_uses_certifi(monkeypatch):
    seen: dict = {}

    def fake_create_default_context(**kwargs):
        seen.update(kwargs)
        return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    monkeypatch.setattr(art.ssl, "create_default_context", fake_create_default_context)
    art._ssl_context()
    assert seen.get("cafile") == certifi.where()
