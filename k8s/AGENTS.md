<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-10-17 | Updated: 2026-10-17 -->

# k8s

## Purpose
Kubernetes manifests for running the analyzer. Applied with `kubectl apply -f k8s/` and verified on
Docker Desktop's local cluster (2/2 pods ready, page served on `http://localhost`).

## Key Files
| File | Description |
|------|-------------|
| `configmap.yaml` | `iam-analyzer-config`: `APP_TITLE`, `DEFAULT_CONTAMINATION`, `SAMPLE_SEED`, `MAX_ROWS`, injected as env vars |
| `deployment.yaml` | 2 replicas, rolling update (`maxUnavailable: 0`), readiness/liveness probes on `/_stcore/health`, non-root, all capabilities dropped, CPU/memory requests and limits |
| `service.yaml` | `LoadBalancer` on port 80 to container port 8501 (published on localhost by Docker Desktop) |

## Subdirectories
None.

## For AI Agents

### Working In This Directory
- The Deployment pulls `ghcr.io/scara0301/cloud-iam-analyzer:latest`, so that GHCR package must be public (or add an `imagePullSecret`). Pin a `sha-<commit>` tag for real deployments.
- `runAsUser: 10001` must match the `useradd --uid 10001` in the `Dockerfile`; `runAsNonRoot` needs a numeric UID.
- Docker Desktop does not publish plain NodePorts to Windows; keep `type: LoadBalancer` for local use. Use `kubectl port-forward svc/iam-analyzer 8501:80` as a universal fallback.
- Container port is named `http` and referenced by name in probes and the Service; rename in all places together.

### Testing Requirements
- With a cluster: `kubectl apply -f k8s/`, `kubectl rollout status deployment/iam-analyzer`, then request `/_stcore/health`.
- Without a cluster, only YAML syntax can be checked (`kubectl apply --dry-run=client` still needs a reachable API server for discovery).

### Common Patterns
- Every object carries the label `app: iam-analyzer`; selectors match on it.

## Dependencies

### Internal
- Image built from the root `Dockerfile` and published by `.github/workflows/ci.yml`.
- Env var names must match `iam_analyzer/config.py`.

### External
- A Kubernetes cluster (Docker Desktop, kind, minikube or cloud) and `kubectl`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
