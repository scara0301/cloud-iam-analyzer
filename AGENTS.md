<!-- Generated: 2026-10-17 | Updated: 2026-10-17 -->

# cloud-iam-analyzer

## Purpose
Streamlit dashboard that detects suspicious API activity (IsolationForest over CloudTrail / Azure
Activity / GCP Audit logs) and over-privileged IAM roles (static policy analysis), packaged with a
DevSecOps toolchain: multi-stage Docker image, GitHub Actions with a Trivy vulnerability gate and
GHCR publish, and Kubernetes manifests. Public repo: `github.com/scara0301/cloud-iam-analyzer`.

## Key Files
| File | Description |
|------|-------------|
| `app.py` | Streamlit entrypoint: sidebar inputs, metric tiles, two tabs (activity anomalies, IAM analysis) |
| `Dockerfile` | Two-stage `python:3.11-slim` build, non-root UID 10001, healthcheck on `/_stcore/health` |
| `.dockerignore` | Keeps tests, k8s, CI, docs and venv out of the build context |
| `requirements.txt` | Runtime deps (streamlit, pandas, numpy, scikit-learn, plotly) |
| `requirements-dev.txt` | Runtime deps plus pytest, black, flake8 |
| `pyproject.toml` | black (line length 100, py311) and pytest (`pythonpath = ["."]`, `testpaths`) config |
| `.flake8` | flake8 config (line length 100, ignores E203/W503) |
| `README.md` | Human-facing run / deploy / CI instructions |
| `WALKTHROUGH-python.md` | Line-by-line explanation of `app.py`, `iam_analyzer/` and `tests/` |
| `WALKTHROUGH-devops.md` | Line-by-line explanation of Dockerfile, CI workflow, K8s manifests, config files |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `iam_analyzer/` | Analytics package: loaders, anomaly model, IAM analysis, charts, sample data (see `iam_analyzer/AGENTS.md`) |
| `tests/` | pytest suite, 18 tests (see `tests/AGENTS.md`) |
| `k8s/` | Kubernetes Deployment, Service, ConfigMap (see `k8s/AGENTS.md`) |
| `.github/` | GitHub Actions CI/CD (see `.github/AGENTS.md`) |
| `.devcontainer/` | VS Code DevContainer config (see `.devcontainer/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Python 3.11 is the container/CI target; the local `.venv` runs a newer Python. Do not use syntax newer than 3.11.
- Run the exact CI gates before pushing: `black --check .`, `flake8 app.py iam_analyzer tests`, `pytest`.
  Use the bare `pytest` command (CI does); it relies on `pythonpath = ["."]` in `pyproject.toml`.
- On Windows PowerShell 5.1, `Get-Content`/`Set-Content` can corrupt UTF-8 (mojibake arrows, added BOM).
  Edit files with the Edit/Write tools, not PowerShell read-modify-write.
- `Dockerfile` copies only `app.py` and `iam_analyzer/`; new top-level runtime files must be added there.
- Pushing to `main` triggers CI and publishes `ghcr.io/scara0301/cloud-iam-analyzer`.

### Testing Requirements
- `pytest` (18 tests, ~5-10 s). The anomaly test asserts at least 70% recall on the injected attack.
- After changing the `Dockerfile`, run `docker build` and the Trivy gate locally
  (`docker run --rm -v //var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.75.0 image --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 <image>`).

### Common Patterns
- Every provider's logs are normalised to one flat schema (`iam_analyzer.loaders.COLUMNS`); analytics never see raw provider fields.
- Config comes from environment variables (`iam_analyzer/config.py`), injected by the K8s ConfigMap.

## Dependencies

### Internal
- `iam_analyzer/` is imported by `app.py` and `tests/`.

### External
- streamlit, pandas, numpy, scikit-learn, plotly (runtime); pytest, black, flake8 (dev).
- Docker, kubectl, GitHub Actions, Trivy (DevOps).

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
