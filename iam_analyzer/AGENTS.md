<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-10-17 | Updated: 2026-10-17 -->

# iam_analyzer

## Purpose
The analytics package behind the dashboard. Data flows one way: `loaders` (raw logs to a normalised
table) then `anomaly` (score each event), while `iam` analyses role policies separately; `viz`
turns both results into Plotly figures; `sample` generates synthetic input; `config` reads settings.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Package marker and `__version__` |
| `config.py` | `Settings` dataclass loaded from env vars (`APP_TITLE`, `DEFAULT_CONTAMINATION`, `SAMPLE_SEED`, `MAX_ROWS`) |
| `loaders.py` | `load_events()` parses CloudTrail/Azure/GCP JSON, NDJSON or CSV into the `COLUMNS` schema; raises `LogFormatError` |
| `anomaly.py` | `build_features()`, `detect_anomalies()` (IsolationForest) and rule-based `reasons` |
| `iam.py` | `analyze_policies()` returns `(findings, hierarchy)` frames; `role_risk_summary()` ranks roles |
| `viz.py` | `anomaly_geo_map`, `anomaly_timeline`, `iam_sunburst`; each handles empty input |
| `sample.py` | `generate_cloudtrail()` (with an injected attacker), `attack_marker()`, `sample_policies()` |

## Subdirectories
None. (`__pycache__/` is generated and ignored.)

## For AI Agents

### Working In This Directory
- Keep the normalised schema in `loaders.COLUMNS` as the single contract; `anomaly.py` and `viz.py` depend on these column names (`event_time`, `user`, `event_name`, `source_ip`, `country_iso3`, `error_code`, ...).
- Adding a model feature means updating both `build_features()` and the `FEATURES` list in `anomaly.py`.
- IAM risk scores are integers 0-4 (`RISK_LABELS` in `iam.py`); `viz.iam_sunburst` fixes its colour range to (0, 4).
- Audit logs have no geolocation: `country_iso3` is an enrichment column; missing values become `UNK` and are excluded from the map.
- Python 3.11 compatible code only; modules use `from __future__ import annotations`.

### Testing Requirements
- Behaviour changes need matching tests in `tests/`. `sample.generate_cloudtrail(seed=42)` is deterministic; tests depend on it, so changing sample data can change results.
- Run `pytest`, `black --check .`, `flake8 app.py iam_analyzer tests` from the repo root.

### Common Patterns
- Private helpers are prefixed `_`; public functions have docstrings.
- Functions take and return pandas DataFrames and never mutate their input (they copy first).
- Empty or tiny inputs return empty or zeroed results instead of raising (e.g. fewer than 10 events means no anomalies).

## Dependencies

### Internal
- `viz.py` imports `UNKNOWN_COUNTRY` from `loaders.py`. Other modules are independent.

### External
- pandas, numpy, scikit-learn (`IsolationForest`), plotly (`express`, `graph_objects`).

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
