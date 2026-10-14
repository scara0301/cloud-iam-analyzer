# Cloud Security Posture & IAM Privilege Analyzer

Streamlit dashboard that detects identity misconfigurations, excessive admin privileges and
suspicious API activity from cloud audit logs, delivered through a DevSecOps pipeline.

| Layer | Implementation |
|---|---|
| Telemetry | AWS CloudTrail, Azure Activity Log, GCP Audit Log (JSON / NDJSON / CSV) |
| Analytics | pandas + scikit-learn `IsolationForest` over per-event behavioural features |
| IAM analysis | Static policy analysis: admin `*:*`, wildcard high-impact services, privilege-escalation primitives, open trust policies |
| Visualisation | Plotly choropleth (anomalous activity by country), sunburst (role → policy → service, coloured by risk) |
| Packaging | Multi-stage `python:3.11-slim` image, non-root (UID 10001), `.dockerignore` |
| CI/CD | GitHub Actions: black, flake8, pytest → build → **Trivy gate** → publish to GHCR |
| Orchestration | Kubernetes Deployment (2 replicas, probes), Service (NodePort / LoadBalancer), ConfigMap |

## Run it

```bash
# locally
pip install -r requirements-dev.txt
streamlit run app.py          # http://localhost:8501 - uses built-in synthetic sample data

# quality gates (same as CI)
black --check . && flake8 app.py iam_analyzer tests && pytest

# container
docker build -t cloud-iam-analyzer .
docker run --rm -p 8501:8501 cloud-iam-analyzer
```

Open the folder in VS Code and choose **Reopen in Container** to use `.devcontainer/` (Python 3.11,
Docker CLI via Docker Desktop/WSL2, kubectl).

## Deploy to Kubernetes

The manifest points at `ghcr.io/scara0301/cloud-iam-analyzer`; change it if you fork. Then:

```bash
kubectl apply -f k8s/
kubectl rollout status deployment/iam-analyzer
# NodePort service -> http://localhost:30501 (Docker Desktop / kind / minikube)
# or: kubectl port-forward svc/iam-analyzer 8501:80
```

Tunables (`DEFAULT_CONTAMINATION`, `MAX_ROWS`, `APP_TITLE`, `SAMPLE_SEED`) live in
`k8s/configmap.yaml`. Readiness/liveness probes hit Streamlit's `/_stcore/health`.
For a private GHCR package add an `imagePullSecret`.

## CI/CD pipeline

`.github/workflows/ci.yml`

1. **lint-test** - `black --check`, `flake8`, `pytest` on Python 3.11.
2. **build-scan-publish** - builds the image on every run (build validation), then
   `trivy image` fails the job on any fixable HIGH/CRITICAL vulnerability (the DevSecOps gate).
   Only after the gate passes, and only for pushes to `main` or `v*` tags, the image is pushed to
   `ghcr.io/<owner>/<repo>` tagged `sha-<commit>`, branch, semver and `latest`. A SARIF report is
   uploaded to GitHub code scanning.

## Input formats

* **AWS CloudTrail** - `{"Records": [...]}`, a bare list, NDJSON, or a CSV with `eventTime,eventName,eventSource,...`
* **Azure Activity Log** - `{"value": [...]}` with `eventTimestamp`, `operationName`, `caller`, `callerIpAddress`
* **GCP Audit Log** - entries with `protoPayload.methodName`, `...principalEmail`, `...callerIp`
* **IAM policies** - `{"roles": [{"name", "trust_policy", "policies": [{"name", "document"}]}]}`
  (see `iam_analyzer/sample.py:sample_policies`)

Audit logs contain no geolocation. The world map uses an optional `country_iso3` column
(e.g. added by a GeoIP enrichment step); events without it are grouped as `UNK` and left off the map.

## How anomalies are scored

Each event gets features describing how unusual it is globally and for that identity: event rarity,
user-event rarity, user-country and user-IP rarity, hour of day (cyclic), error flag, sensitive-action
flag, and API burst rate. `IsolationForest` scores them; the top `contamination` fraction (sidebar
slider) is flagged. A rule layer attaches readable reasons (e.g. *unusual country for user*,
*sensitive IAM/logging action*). The synthetic data includes a compromised `svc-deploy` account doing
recon → privilege escalation → CloudTrail tampering from an unfamiliar country at 03:00 UTC; the test
suite asserts at least 70% of that activity is flagged.
