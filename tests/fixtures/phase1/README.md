# Phase 1 fixtures

Both files were produced by the committed Phase 1 code (`ac4e180`) so the
migration tests exercise genuine historical data rather than a hand-written
approximation.

- `database.json`: every row of a Phase 1 SQLite database (`profiles`, `rubrics`,
  `experiments`, `runs`, `evaluations`, `findings`, `overrides`) with the original
  column order. `tests/test_migration.py` rebuilds the version 1 schema from the
  DDL embedded in that test and inserts these rows.
- `report.v1.json`: the Phase 1 JSON report export for the same data, including a
  legacy human override. It proves that historical exports still load and can be
  re-exported as report format 2.0.0.

To regenerate (only needed if the Phase 1 contract is ever redefined):

```sh
git worktree add --detach /tmp/phase1 ac4e180
PYTHONPATH=/tmp/phase1/src .venv/bin/python -m faultline \
  --db /tmp/phase1/out/history.sqlite3 demo --behavior vulnerable \
  --output /tmp/phase1/out/demo
# append one override, export, then dump the tables to database.json
git worktree remove /tmp/phase1
```

The identifiers and timestamps are the ones produced by that run; they are data,
not assertions. The tests only require them to stay internally consistent.
