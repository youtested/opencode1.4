# tests/slow

Tests that are real but expensive: they spawn subprocesses (`python -m pytest`,
`node`, shell), wait on wall-clock deadlines, or drive a live server socket.
Each one costs seconds on a phone, and they made the default suite 5m52s for
1,433 tests.

They are skipped by default via `norecursedirs` in `pyproject.toml`. Run them
explicitly when touching the subsystem they cover:

    python -m pytest tests/slow -q

Everything in `tests/` (outside this directory) should stay under ~60s total so
editing stays cheap.
