"""The skills-only edition submitted to the Claude plugin directory.

The directory accepts a plugin from an organization it has not verified only
when the folder holds instructions and nothing that runs: no hooks, no scripts,
no inline shell, and no tool pre-approval beyond reading and searching. These
tests keep `directory/tenuo` inside those rules, so a change that would be
refused at submission fails here first.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
EDITION = REPO / "directory" / "tenuo"
FULL_PLUGIN = REPO / "plugins" / "tenuo"
ALLOWED_SUFFIXES = {".md", ".txt", ".json", ".yaml", ".yml", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico"}
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico"}
READ_ONLY_TOOLS = {"Read", "Grep", "Glob", "LS"}
SKILLS = ("setup", "status", "audit")


def files() -> list[Path]:
    return sorted(p for p in EDITION.rglob("*") if p.is_file())


def frontmatter(skill: str) -> tuple[dict, str]:
    text = (EDITION / "skills" / skill / "SKILL.md").read_text(encoding="utf-8")
    _, front, body = text.split("---\n", 2)
    return dict(line.split(": ", 1) for line in front.strip().splitlines()), body


def test_the_folder_holds_only_instructions_and_images():
    names = {p.relative_to(EDITION).as_posix() for p in files()}
    assert names == {".claude-plugin/plugin.json", "README.md", "icon.png",
                     *(f"skills/{s}/SKILL.md" for s in SKILLS)}
    for path in files():
        assert path.suffix.lower() in ALLOWED_SUFFIXES, path
        assert not path.is_symlink(), path
        raw = path.read_bytes()
        assert not raw.startswith(b"#!"), f"{path} starts like a script"
        if path.suffix.lower() not in IMAGE_SUFFIXES:
            assert b"\x00" not in raw
            raw.decode("utf-8")
    # Nothing that Claude Code would load as code or configuration.
    for forbidden in ("hooks", "scripts", "bin", "commands", "agents", "monitors.json",
                      ".mcp.json", ".lsp.json", "settings.json"):
        assert not (EDITION / forbidden).exists(), forbidden


def test_manifest_is_complete_and_matches_the_full_plugin():
    manifest = json.loads((EDITION / ".claude-plugin" / "plugin.json").read_text())
    full = json.loads((FULL_PLUGIN / ".claude-plugin" / "plugin.json").read_text())
    assert manifest["name"] == "tenuo"
    assert re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?", manifest["name"])
    # One version line for both editions, so a release moves them together.
    assert manifest["version"] == full["version"]
    assert manifest["license"] == "Apache-2.0"
    for field in ("description", "author", "homepage", "repository"):
        assert manifest[field]
    for field in ("documentationUrl", "supportUrl", "privacyPolicyUrl", "termsOfServiceUrl"):
        assert manifest[field].startswith("https://")
    assert manifest["icon"] == "./icon.png" and (EDITION / "icon.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    # Component keys would point Claude Code at things this edition must not have.
    assert not {"hooks", "mcpServers", "lspServers", "commands", "agents", "monitors"} & set(manifest)


@pytest.mark.parametrize("skill", SKILLS)
def test_skills_are_plain_instructions(skill):
    meta, body = frontmatter(skill)
    assert meta["name"] == skill
    assert "Use when" in meta["description"] and len(meta["description"]) <= 1536
    # Claude can start them from a plain request.
    assert "disable-model-invocation" not in meta
    # No tool pre-approval beyond reading and searching, and no plugin paths.
    granted = set(re.split(r"[,\s]+", meta.get("allowed-tools", "").strip())) - {""}
    assert granted <= READ_ONLY_TOOLS
    text = (EDITION / "skills" / skill / "SKILL.md").read_text()
    assert "${" not in text, "no variable paths"
    # No inline shell: neither the one-line form nor a fenced block that runs.
    assert not re.search(r"(^|\s)!`", text)
    assert "```!" not in text
    # Nothing that changes where packages come from, and nothing piped to a shell.
    assert not re.search(r"--index-url|--extra-index-url|--registry|\bcurl\b[^\n]*\|\s*(sh|bash)", text)


def test_readme_meets_the_listing_rules_and_discloses_behaviour():
    text = (EDITION / "README.md").read_text()
    outside_code = re.sub(r"```.*?```", "", text, flags=re.S)
    assert len(outside_code.split()) >= 40
    for needed in ("PyPI", "tenuo-authorizer", ".claude/settings.json", "~/.tenuo",
                   "observe-only", "127.0.0.1", "privacy"):
        assert needed in text, needed
    # Images in the README must be raster files that ship in the folder.
    assert ".svg" not in text


def test_the_full_plugin_stays_out_of_the_way_of_this_edition():
    """The repository's own marketplace lists the full plugin only; the edition
    here is found through the directory, by submitting this folder."""
    market = json.loads((REPO / ".claude-plugin" / "marketplace.json").read_text())
    assert [entry["source"] for entry in market["plugins"]] == ["./plugins/tenuo"]
