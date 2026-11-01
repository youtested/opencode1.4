import sys
from pathlib import Path

import pytest

# ensure the source package is importable even without the editable install
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(autouse=True)
def _isolate_data_dir(tmp_path, monkeypatch):
    """Point every test's data dir at a scratch path.

    Without this, any test that drives a tool which persists state (the
    per-session snapshot store, the patch journal, session autosave) writes into
    the developer's REAL ~/.local/share/opencode_py. That pollution is invisible,
    survives the run, and is exactly how real user data was deleted once already.
    Tests needing a specific data dir set it themselves with their own monkeypatch,
    which simply overrides this one.
    """
    from opencode_py.globals import Path as GPath

    monkeypatch.setattr(GPath, "data", tmp_path / "data")
    # The symbol index + repo map (index/repomap.py) cache under GPath.cache.
    # Without this, a test that builds a system prompt against a real repo
    # writes into the developer's REAL ~/.cache/opencode_py/symbols.
    monkeypatch.setattr(GPath, "cache", tmp_path / "cache")
    # Thread-locals installed by the agent loop (the snapshot session, the
    # glob/apply_patch worktree) survive between tests on the same thread, so a
    # test that ran after a loop-driven one would silently inherit the previous
    # test's project. Clearing both keeps every test independent.
    from opencode_py import snapshots as _snaps
    from opencode_py.tools import apply_patch as _ap
    from opencode_py.tools import glob as _glob

    _snaps.set_session("", "")
    _ap.set_worktree(None)
    _glob.set_worktree(None)
    yield
    _snaps.set_session("", "")
    _ap.set_worktree(None)
    _glob.set_worktree(None)
