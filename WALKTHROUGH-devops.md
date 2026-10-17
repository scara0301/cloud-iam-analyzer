# DevOps code walkthrough (line by line)

Covers the `Dockerfile`, `.github/workflows/ci.yml`, the three `k8s/` manifests, and the small
config files. The Python code is in `WALKTHROUGH-python.md`.

## 0. Vocabulary

| Term | Meaning |
|---|---|
| **Image** | a frozen, shareable package containing your app plus its operating system files |
| **Container** | a running copy of an image |
| **Layer** | each Dockerfile instruction adds one layer; Docker caches unchanged layers |
| **Multi-stage build** | one Dockerfile with several `FROM` stages; only the last stage ships, so build tools stay out of the final image |
| **venv** | a Python virtual environment: an isolated folder of installed packages |
| **UID** | numeric user id; UID 0 is root (all-powerful) |
| **CVE** | a publicly catalogued security vulnerability |
| **Trivy** | an open-source scanner that checks images for known CVEs |
| **GHCR** | GitHub Container Registry, where the image is published (`ghcr.io`) |
| **CI/CD** | automatic checks and delivery run on every push |
| **Pod** | the smallest Kubernetes unit: one or more containers run together |
| **Deployment** | a Kubernetes object that keeps N identical pods running and does rolling updates |
| **Service** | a stable network address that load-balances across matching pods |
| **ConfigMap** | key/value settings stored in the cluster and handed to pods |
| **Probe** | a health check Kubernetes runs against a container |
| **Label / selector** | tags on objects / the query that finds objects by tag |

---

## 1. `Dockerfile` (45 lines)

- **L1** `# syntax=docker/dockerfile:1`: a special comment telling the builder which Dockerfile language version to use (the latest 1.x), enabling modern features.
- **L3** comment marking Stage 1.
- **L4** `FROM python:3.11-slim AS builder`: start a stage from the official Python 3.11 image, the "slim" Debian variant (smaller than the full image), and name the stage `builder`.
- **L6-7** `ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1`: set environment variables. The first stops pip keeping its download cache (smaller layers); the second skips pip's "new version available" network check. The backslash continues the instruction onto the next line.
- **L9** `RUN python -m venv /opt/venv`: run a command at build time; create a virtual environment at `/opt/venv`. The point of a venv is that the final stage can copy one folder.
- **L10** `ENV PATH="/opt/venv/bin:$PATH"`: put the venv's `bin` first on the command search path, so `pip` and `python` now mean the venv's versions.
- **L12** `WORKDIR /build`: set (and create) the working directory for following instructions.
- **L13** `COPY requirements.txt .`: copy only the requirements file into the image (the `.` is the working directory). Copying it *before* the app code means Docker can reuse the cached dependency layer unless the requirements change.
- **L14-15** `RUN pip install -r requirements.txt && pip uninstall -y setuptools wheel`: install all dependencies into the venv, then (`&&` = only if the first succeeded) remove `setuptools` and `wheel`, which a venv on Python 3.11 includes but the app never uses. `-y` skips the confirmation prompt.
- **L17** comment marking Stage 2.
- **L18** `FROM python:3.11-slim AS runtime`: a *fresh* image for the final stage. Nothing from the builder survives unless copied explicitly (L31).
- **L20-22** `ENV PYTHONDONTWRITEBYTECODE=1` (don't write `.pyc` cache files), `PYTHONUNBUFFERED=1` (print logs immediately instead of buffering, so `docker logs` is live) and the same `PATH` trick so `streamlit` resolves to the venv's copy.
- **L24-26** comments: the base image carries `setuptools` and `wheel` (with vendored sub-packages) that have HIGH-severity CVEs and are unused at runtime, so they are removed; and a fixed numeric UID is used so Kubernetes can verify the container is non-root.
- **L27-28** `RUN /usr/local/bin/python -m pip uninstall -y setuptools wheel && useradd --create-home --uid 10001 appuser`: remove them from the *system* Python using its full path (the PATH now points at the venv), then create a regular user `appuser` with UID 10001 and a home directory. This is what made the Trivy gate pass.
- **L30** `WORKDIR /app`: the app lives in `/app`.
- **L31** `COPY --from=builder /opt/venv /opt/venv`: the multi-stage trick: copy the finished venv out of the builder stage. Compilers and pip caches stay behind.
- **L32** `COPY --chown=10001:10001 app.py ./`: copy the entrypoint, owned by the app user.
- **L33** `COPY --chown=10001:10001 iam_analyzer ./iam_analyzer`: copy the package. Only these two paths are copied: tests, docs and k8s files never enter the image.
- **L35** `USER 10001`: from here on, and when the container runs, act as UID 10001, not root. If an attacker breaks into the app, they are not root.
- **L36** `EXPOSE 8501`: documents that the app listens on port 8501 (Streamlit's default). It does not publish the port by itself.
- **L38-39** `HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD python -c "..."`: Docker runs the command every 30 s; each try may take at most 5 s; failures in the first 20 s are ignored while the app boots; 3 consecutive failures mark the container unhealthy. The command is a tiny Python one-liner that opens `http://127.0.0.1:8501/_stcore/health` with `urllib` (Streamlit's built-in health endpoint). It uses Python because the slim image has no `curl`. An HTTP error or timeout makes it exit non-zero.
- **L41-45** `ENTRYPOINT ["streamlit", "run", "app.py", ...]`: the program that runs when the container starts. The list ("exec form") runs it directly rather than through a shell:
  - `--server.port=8501`: listen on 8501.
  - `--server.address=0.0.0.0`: listen on all network interfaces (the default, localhost only, would be unreachable from outside the container).
  - `--server.headless=true`: don't try to open a browser or ask for an email.
  - `--browser.gatherUsageStats=false`: no telemetry.

## 2. `.dockerignore`

Lists paths excluded from the *build context* (what Docker is sent when you run `docker build`):
`.git`, `.github`, `.devcontainer`, `.venv` (hundreds of MB of local packages), `.pytest_cache`,
`.omc`, `__pycache__`, `*.pyc`, `tests`, `k8s`, `Dockerfile`, `.dockerignore`, `README.md`,
`WALKTHROUGH-*.md`, `**/AGENTS.md` (documentation at any depth), `requirements-dev.txt`, `.flake8`
and `pyproject.toml`. Smaller context = faster builds and no accidental secrets or junk in the image.

---

## 3. `.github/workflows/ci.yml` (119 lines): the pipeline

YAML basics: indentation defines structure; `key: value` pairs; `-` starts a list item.

### Triggers and settings (1-15)
- **L1** `name: CI`: label shown in the Actions tab.
- **L3-8** `on:` when to run: on `push` to the `main` branch or any tag matching `v*`, and on `pull_request` targeting `main`.
- **L10-11** `permissions: contents: read`: the default token can only read the repo (least privilege). Jobs that need more ask for it individually.
- **L13-15** `env:` variables for every job. `IMAGE_NAME: ghcr.io/${{ github.repository }}` builds the image name from the repo path (`${{ ... }}` is GitHub's expression syntax); `TRIVY_IMAGE: aquasec/trivy:0.75.0` pins the scanner version.

### Job 1: `lint-test` (17-39)
- **L17** `jobs:`. **L18** job id `lint-test`. **L19** `name:` display name. **L20** `runs-on: ubuntu-latest`: a fresh Ubuntu virtual machine.
- **L21** `steps:` run in order; if one fails, the job stops.
- **L22** `uses: actions/checkout@v4`: download the repository's code onto the runner.
- **L24-28** `actions/setup-python@v5` with `python-version: "3.11"` (quoted so YAML doesn't read it as the number 3.11, which would drop trailing zeros for e.g. 3.10), `cache: pip` (cache downloaded packages between runs) and `cache-dependency-path` (the file whose contents form the cache key).
- **L30** `run: pip install -r requirements-dev.txt`: install runtime and dev tools. `run:` executes a shell command.
- **L32-33** `black --check .`: fail if any file isn't formatted the way black would format it (does not change files).
- **L35-36** `flake8 app.py iam_analyzer tests`: style and error linting of exactly those paths.
- **L38-39** `pytest`: run the 18 tests. This needs `pythonpath = ["."]` in `pyproject.toml`.

### Job 2: `build-scan-publish` (41-119)
- **L41-44** `needs: lint-test`: wait for job 1 and only run if it passed. Runs on its own fresh VM.
- **L45-48** `permissions` for this job: `contents: read`, `packages: write` (push to GHCR), `security-events: write` (upload scan results).
- **L50** checkout again (separate machine). **L52** `docker/setup-buildx-action@v3`: set up Docker Buildx, the modern builder with cache support.
- **L54-63** step `Image metadata` with `id: meta` so later steps can read its output. `docker/metadata-action@v5` computes image tags and labels. `tags:` rules: `type=sha` (e.g. `sha-1a2b3c4`), `type=ref,event=branch` (e.g. `main`), `type=semver,pattern={{version}}` (for tags like `v1.2.0`), and `type=raw,value=latest,enable={{is_default_branch}}` (`latest` only on the default branch). The `|` after `tags:` means a multi-line text block.
- **L65-73** `Build image` with `docker/build-push-action@v6`: `context: .` (build from the repo root); `load: true` (keep the result in the runner's local Docker so the scanner can see it, without pushing); `tags:` a temporary tag `<image>:ci`; `cache-from`/`cache-to: type=gha` use GitHub's cache so repeat builds are faster. This is the build validation: a broken Dockerfile fails here.
- **L75-83** step `Trivy gate`: the DevSecOps gate. `docker run --rm` starts the scanner container and deletes it afterwards; `-v /var/run/docker.sock:/var/run/docker.sock` lets it talk to the host's Docker to read the image we just built; `${{ env.TRIVY_IMAGE }} image` runs Trivy's image scan; `--scanners vuln` checks vulnerabilities only; `--severity HIGH,CRITICAL` ignores lower severities; `--ignore-unfixed` ignores CVEs with no available fix (nothing could be done about them); `--exit-code 1` makes Trivy return failure if anything is found, which fails the job; `"$IMAGE_NAME:ci"` is the image to scan. Backslashes continue the command across lines.
- **L85-93** step `Trivy report (SARIF)`: `if: always()` runs even if the gate failed. It adds `-v "$PWD:/work" -w /work` to write a file into the checkout, scans MEDIUM too, `--format sarif --output trivy-results.sarif` produces a standard security-report file, and `--exit-code 0` so this step never fails.
- **L95-100** `Upload SARIF to code scanning`: `if: always() && github.event_name != 'pull_request'` runs on non-PR events; `continue-on-error: true` means a failure here (for example code scanning not enabled on a private repo) doesn't fail the pipeline; `github/codeql-action/upload-sarif@v3` uploads the file so findings appear in GitHub's Security tab.
- **L102-108** `Log in to GHCR` only for non-PR runs: `docker/login-action@v3` with `registry: ghcr.io`, `username: ${{ github.actor }}` (who triggered the run) and `password: ${{ secrets.GITHUB_TOKEN }}` (a temporary token GitHub creates for each run; no secret to manage).
- **L110-119** `Publish to GHCR` (non-PR only): `build-push-action@v6` again with `push: true`, `tags: ${{ steps.meta.outputs.tags }}` (the list computed on L54-63) and `labels:` metadata. Because Docker layers are cached, this is quick. It is placed after the scan, so a vulnerable image is never published.

---

## 4. `k8s/configmap.yaml` (11 lines)
- **L1** `apiVersion: v1` and **L2** `kind: ConfigMap`: which API and which type of object.
- **L3-6** `metadata`: `name: iam-analyzer-config` (referenced by the Deployment) and `labels: app: iam-analyzer`.
- **L7-11** `data:` four string settings: `APP_TITLE`, `DEFAULT_CONTAMINATION: "0.03"`, `SAMPLE_SEED: "42"`, `MAX_ROWS: "200000"`. All values are quoted because ConfigMap values must be strings. They match what `iam_analyzer/config.py` reads.

## 5. `k8s/deployment.yaml` (63 lines)
- **L1-2** `apps/v1`, `kind: Deployment`. **L3-6** name `iam-analyzer` and a label.
- **L8** `replicas: 2`: keep two pods running (one can restart without downtime).
- **L9-11** `selector.matchLabels app: iam-analyzer`: this Deployment manages pods carrying that label.
- **L12-16** `strategy: RollingUpdate` with `maxUnavailable: 0` (never drop below 2 ready pods during an update) and `maxSurge: 1` (allow one extra pod temporarily).
- **L17-20** `template`: the blueprint for each pod; its labels must match the selector.
- **L22-26** pod-level `securityContext`: `runAsNonRoot: true` (refuse to start if the image would run as root), `runAsUser: 10001` (same UID as the Dockerfile), and `seccompProfile: RuntimeDefault` (a default filter blocking dangerous system calls).
- **L27-28** `containers:` list with one entry named `app`.
- **L29-30** comment and `image: ghcr.io/scara0301/cloud-iam-analyzer:latest`. For production, pin a `sha-<commit>` tag so deployments are reproducible.
- **L31** `imagePullPolicy: IfNotPresent`: only download if the node doesn't already have this image.
- **L32-34** `ports`: a port named `http`, container port 8501. Naming lets the probes and Service refer to it by name.
- **L35-37** `envFrom: configMapRef: name: iam-analyzer-config`: turn every key in the ConfigMap into an environment variable.
- **L38-44** `readinessProbe`: "is it ready for traffic?" An HTTP GET to `/_stcore/health` on port `http`; first check after 5 s (`initialDelaySeconds`), then every 10 s (`periodSeconds`), each waiting at most 3 s (`timeoutSeconds`). A pod failing it is removed from the Service's endpoints but not killed.
- **L45-52** `livenessProbe`: "is it alive?" Same endpoint, first check after 20 s, every 20 s, 3 s timeout, and `failureThreshold: 3`: after 3 consecutive failures Kubernetes restarts the container.
- **L53-59** `resources`: `requests` (what the scheduler reserves: 250 millicores of CPU, 512 MiB memory) and `limits` (hard caps: 1 CPU, 1 GiB; exceeding memory gets the container killed). `"1"` is quoted to stay a string.
- **L60-63** container `securityContext`: `allowPrivilegeEscalation: false` (can't gain extra privileges) and `capabilities: drop: ["ALL"]` (remove all special Linux powers).

## 6. `k8s/service.yaml` (18 lines)
- **L1-6** `v1`, `kind: Service`, name `iam-analyzer`, label.
- **L8-10** comments: why `LoadBalancer` is used (Docker Desktop publishes it on localhost; plain NodePorts are not reachable from Windows).
- **L11** `type: LoadBalancer`: asks the platform for an external address. On Docker Desktop it appears as `localhost:80`; on a cloud it becomes a public IP.
- **L12-13** `selector: app: iam-analyzer`: send traffic to pods with this label.
- **L14-18** `ports`: name `http`; `port: 80` (what clients connect to); `targetPort: http` (the container port named `http`, i.e. 8501); `nodePort: 30501` (the fixed port opened on every cluster node; a LoadBalancer Service still allocates one).

---

## 7. Small configuration files

### `.devcontainer/devcontainer.json`
- `"image"`: `mcr.microsoft.com/devcontainers/python:1-3.11-bookworm`, Microsoft's Python 3.11 development image.
- `"features"`: add-ons: `docker-outside-of-docker` (use the host's Docker from inside the dev container) and `kubectl-helm-minikube` (installs kubectl; `"helm": "none"` skips Helm).
- `"postCreateCommand"`: `pip install -r requirements-dev.txt` runs once after the container is created.
- `"forwardPorts": [8501]` and `portsAttributes`: make Streamlit reachable and label it.
- `"customizations.vscode"`: recommended extensions (Python, Black, Flake8, Docker, Kubernetes, YAML) and settings (pytest enabled, format-on-save, Black as the Python formatter).

### `pyproject.toml`
- `[tool.black]`: `line-length = 100`, `target-version = ["py311"]`.
- `[tool.pytest.ini_options]`: `testpaths = ["tests"]` (where to look), `pythonpath = ["."]` (add the repo root to the import path so `import iam_analyzer` works under bare `pytest`; this fixed a CI failure), `filterwarnings = ["ignore::DeprecationWarning"]` (hide noisy deprecation notices).

### `.flake8`
- `max-line-length = 100` (matches black), `extend-ignore = E203, W503` (two rules that conflict with black's style), `exclude` for `.git`, `__pycache__`, `.venv`.

### `requirements.txt` and `requirements-dev.txt`
- Runtime: `streamlit>=1.40,<2`, `pandas>=2.2,<3`, `numpy>=1.26`, `scikit-learn>=1.5,<2`, `plotly>=5.24,<7`. The `<N` upper bounds block surprise major-version breakage.
- Dev: `-r requirements.txt` (include the runtime file) plus `pytest>=8`, `black>=24`, `flake8>=7`.

### `.gitignore`
- Keeps `.venv/`, `__pycache__/`, `*.pyc`, `.pytest_cache/`, `.omc/` out of git.

---

## 8. How the pieces connect

1. You push code to `main`.
2. `ci.yml` job 1 formats, lints and tests it; job 2 builds the `Dockerfile`, scans the image, and only then pushes `ghcr.io/scara0301/cloud-iam-analyzer`.
3. `k8s/deployment.yaml` pulls that image; `configmap.yaml` supplies settings; `service.yaml` exposes it.
4. The probes call `/_stcore/health`, the same endpoint the Dockerfile's `HEALTHCHECK` uses.
5. UID `10001` ties together the Dockerfile (`useradd`, `USER`) and the Deployment (`runAsUser`).
