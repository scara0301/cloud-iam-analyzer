<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-10-17 | Updated: 2026-10-17 -->

# tests

## Purpose
pytest suite (18 tests) covering parsing, anomaly detection, IAM analysis, figure building and an
end-to-end render of the Streamlit app. All tests use the deterministic synthetic data from
`iam_analyzer/sample.py`, so no cloud access or network is needed.

## Key Files
| File | Description |
|------|-------------|
| `test_loaders.py` | AWS, NDJSON, CSV, Azure and GCP parsing; rejection of unknown schemas and bad JSON |
| `test_anomaly.py` | Column contract, flag rate vs contamination, at least 70% recall on the injected attack, readable reasons, tiny-input safety |
| `test_iam.py` | Expected findings per role, clean read-only role, Deny carries no risk, ranking, empty document |
| `test_app.py` | Figures build and handle empty input; `streamlit.testing.v1.AppTest` renders `app.py` without exceptions |

## Subdirectories
None.

## For AI Agents

### Working In This Directory
- There is no `conftest.py` or `__init__.py`; imports of `iam_analyzer` work because `pyproject.toml` sets `pythonpath = ["."]`. Do not remove it: CI runs bare `pytest` and fails without it.
- `test_anomaly.py` uses a module-scoped fixture so the model trains once; keep that pattern (training dominates runtime).
- `test_app.py` locates `app.py` via `Path(__file__).parents[1]`, so it works from any working directory.

### Testing Requirements
- Run `pytest` from the repo root (both `pytest` and `python -m pytest` must pass).
- If you change `sample.py`, re-check the recall threshold and `("PlatformAdmin", "Full administrator access")`-style expectations.

### Common Patterns
- One behaviour per test; assertions carry a message where the threshold is a tuning knob (recall).
- Test names describe the outcome (`test_deny_statements_carry_no_risk`).

## Dependencies

### Internal
- Imports everything from `iam_analyzer/` and runs `app.py`.

### External
- pytest, `streamlit.testing.v1.AppTest`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
