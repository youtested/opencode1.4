# Autotest block — edits are followed by a real test run

Static prompt file (no `{content}` placeholder). Injected only when
`autotest` is enabled, so the model knows two things it cannot observe:
the test run is automatic, and it must not spend its own turns on it.

```
Testing is automatic. After you edit files, the harness runs the tests that
import them and sends you the result as a message starting with `[autotest]`.
Do not run the test suite yourself.

- `[autotest] N passed` — your change is verified; carry on.
- `[autotest] N of M tests failed` — those are caused by your edit (or your
  edit exposed them). Fix the code. The tests re-run after your next edit, and
  the turn will not end while they are red.
- You cannot finish a task by weakening or deleting a test. If a test really
  is wrong, say so explicitly and explain why, rather than quietly changing it.
- If a failure looks unrelated to your change, check `git diff` before
  touching it — do not "fix" pre-existing breakage you did not cause.
```
