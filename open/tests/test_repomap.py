"""Repo map: ranked project outline injected into the system prompt."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from opencode_py.agent.system import _REPO_MAP_LABEL, build_system_prompt, labeled_prompt_parts
from opencode_py.config import Config
from opencode_py.index.repomap import render_repo_map, warm
from opencode_py.util.truncate import estimate_tokens


def _prompt(repo, cfg, **kw):
    return build_system_prompt(
        directory=repo,
        worktree=repo,
        provider_id="anthropic",
        model_id="claude",
        cfg=cfg,
        **kw,
    )


@pytest.fixture
def repo(tmp_path):
    """A tiny project where one file clearly outranks another."""
    (tmp_path / "alpha.py").write_text(
        "def main():\n    return 1\n\n\ndef helper():\n    return 2\n",
        encoding="utf-8",
    )
    (tmp_path / "beta.py").write_text(
        "import alpha\n\n\n"
        "def entry():\n    return alpha.main()\n\n\n"
        "def cold():\n    return 0\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def warm_repo(repo):
    """The same repo with its index already built, as after the startup warm."""
    warm(repo)
    return repo


# --- renderer ---------------------------------------------------------------


def test_render_includes_files_and_hot_symbols(repo):
    out = render_repo_map(repo, 1200)
    assert out, "a two-file repo must render"
    assert "beta.py" in out
    assert "entry" in out


def test_render_respects_token_budget(repo):
    for i in range(60):
        (repo / f"mod_{i:02d}.py").write_text(
            f"def fn_{i}():\n    return {i}\n", encoding="utf-8"
        )
    budget = 120
    out = render_repo_map(repo, budget)
    assert out
    assert estimate_tokens(out) <= budget


def test_zero_budget_returns_empty(repo):
    assert render_repo_map(repo, 0) == ""


def test_empty_dir_returns_empty(tmp_path):
    assert render_repo_map(tmp_path, 1200) == ""


def test_nonexistent_root_returns_empty(tmp_path):
    assert render_repo_map(tmp_path / "does-not-exist", 1200) == ""


def test_never_raises_on_garbage_input():
    for bad in (None, "", b"\x00", 12345, [], object()):
        assert render_repo_map(bad, 1200) == ""


def test_deterministic_across_calls(repo):
    assert render_repo_map(repo, 1200) == render_repo_map(repo, 1200)


# --- send path must never block --------------------------------------------


def test_nonblocking_cold_index_returns_empty_without_building(repo):
    """blocking=False must NOT walk the tree (that is the first-send cost)."""
    from opencode_py.index.engine import _ENGINE

    assert render_repo_map(repo, 1200, blocking=False) == ""
    # still cold: the send path did not build anything itself
    assert _ENGINE.peek(repo.resolve()) is None


def test_nonblocking_is_instant_when_warm(warm_repo):
    out = render_repo_map(warm_repo, 1200, blocking=False)
    assert out and "beta.py" in out


def test_nonblocking_after_warm_is_fast(warm_repo):
    import time as _t

    render_repo_map(warm_repo, 1200, blocking=False)  # prime the cache
    start = _t.monotonic()
    for _ in range(50):
        render_repo_map(warm_repo, 1200, blocking=False)
    assert (_t.monotonic() - start) < 0.5


def test_send_path_reuses_last_map_from_a_previous_process(warm_repo, monkeypatch):
    """A brand-new process has no index in memory, but the map it rendered last
    time is on disk — turn 1 gets that instead of an empty block."""
    from opencode_py.index import repomap

    expected = render_repo_map(warm_repo, 1200)
    assert expected
    monkeypatch.setattr(repomap, "_CACHE", {})
    monkeypatch.setattr(repomap, "_LAST", {})
    monkeypatch.setattr(repomap, "_LOADED", {})
    from opencode_py.index.engine import _ENGINE

    monkeypatch.setattr(_ENGINE, "_roots", {})

    assert repomap.render_repo_map(warm_repo, 1200, blocking=False) == expected


def test_persisted_map_is_not_rewritten_when_unchanged(warm_repo, monkeypatch):
    """One write per change, not one write per turn."""
    from opencode_py.index import repomap

    saved: list[str] = []
    monkeypatch.setattr(repomap, "_save_last", lambda _root, text: saved.append(text))
    monkeypatch.setattr(repomap, "_LOADED", {})
    for _ in range(2):
        monkeypatch.setattr(repomap, "_CACHE", {})
        render_repo_map(warm_repo, 1200)
    assert len(saved) == 1


def test_fresh_render_beats_a_stale_persisted_map(warm_repo, monkeypatch):
    """Stale text is only a first-turn placeholder; a warm index always wins."""
    from opencode_py.index import repomap

    render_repo_map(warm_repo, 1200)
    path = repomap._last_path(warm_repo.resolve())
    path.write_text("STALE PLACEHOLDER", encoding="utf-8")
    monkeypatch.setattr(repomap, "_CACHE", {})
    monkeypatch.setattr(repomap, "_LAST", {})
    monkeypatch.setattr(repomap, "_LOADED", {})

    got = repomap.render_repo_map(warm_repo, 1200, blocking=False)
    assert "STALE" not in got
    assert "beta.py" in got


# --- prompt wiring ----------------------------------------------------------


def test_prompt_contains_repo_map_block(warm_repo):
    prompt = _prompt(warm_repo, Config())
    assert "Repo map (" in prompt


def test_parts_match_sender_byte_for_byte(warm_repo):
    """Preview and sender must render identical bytes — the map included."""
    cfg = Config()
    sent = build_system_prompt(
        directory=warm_repo, worktree=warm_repo, provider_id="anthropic",
        model_id="claude", cfg=cfg,
    )
    parts = labeled_prompt_parts(
        directory=warm_repo, worktree=warm_repo, provider_id="anthropic",
        model_id="claude", cfg=cfg, query="",
    )
    assert sent == "\n\n".join(text for _label, text in parts)


def test_config_off_removes_block(warm_repo):
    assert "Repo map (" not in _prompt(warm_repo, Config(repo_map=False))


def test_zero_tokens_removes_block(warm_repo):
    assert "Repo map (" not in _prompt(warm_repo, Config(repo_map_tokens=0))


def test_low_data_shrinks_budget(warm_repo):
    # Enough files that the FULL map is far past the save-data cap (500 tokens
    # = 2000 chars): with only a handful of one-line files both budgets render
    # the whole map and the assertion could never tell them apart.
    for i in range(300):
        (warm_repo / f"big_{i:03d}.py").write_text(
            "".join(f"def fn_{i}_{j}():\n    return {j}\n\n\n" for j in range(4)),
            encoding="utf-8",
        )
    warm(warm_repo)  # pick up the new files
    big = _prompt(warm_repo, Config(repo_map_tokens=100000, low_data=True))
    small = _prompt(warm_repo, Config(repo_map_tokens=100000, low_data=False))
    assert estimate_tokens(big) < estimate_tokens(small)


def test_block_lands_after_environment(warm_repo):
    parts = labeled_prompt_parts(
        directory=warm_repo, worktree=warm_repo, provider_id="anthropic",
        model_id="claude", cfg=Config(), query="",
    )
    labels = [label for label, _text in parts]
    assert _REPO_MAP_LABEL in labels
    assert labels[0] == "base.md" and labels[1] == "environment"
    assert labels.index(_REPO_MAP_LABEL) == 2


def test_cold_repo_still_renders_a_prompt(repo):
    """First send: index may be cold, prompt must still build instantly."""
    prompt = _prompt(repo, Config())
    assert prompt and "Base prompt" in prompt


def test_default_config_is_on():
    cfg = Config()
    assert cfg.repo_map is True
    assert cfg.repo_map_tokens == 1200


def test_config_round_trips_through_from_dict(tmp_path):
    cfg = Config.from_dict({"repo_map": False, "repo_map_tokens": 400}, base_dir=tmp_path)
    assert cfg.repo_map is False and cfg.repo_map_tokens == 400
    shown = cfg.as_dict()
    assert shown["repo_map"] is False and shown["repo_map_tokens"] == 400
