<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-10-17 | Updated: 2026-10-17 -->

# workflows

## Purpose
The single CI/CD pipeline. It runs on pushes to `main`, `v*` tags and pull requests to `main`.

## Key Files
| File | Description |
|------|-------------|
| `ci.yml` | Job `lint-test` (black, flake8, pytest on Python 3.11) then job `build-scan-publish` (build, Trivy gate, SARIF report, GHCR publish) |

## Subdirectories
None.

## For AI Agents

### Working In This Directory
- The Trivy gate runs the official image `aquasec/trivy:0.75.0` directly via `docker run`. An earlier version used `aquasecurity/trivy-action`; its binary-install step failed before scanning, so do not reintroduce it without testing.
- Publishing happens only for non-PR events and only after the Trivy gate passes (step order matters: build, scan, login, push).
- Pin third-party actions to tags that exist; verify with `gh api repos/<owner>/<repo>/tags` before committing (an invented tag broke CI once).
- Jobs need `packages: write` (GHCR push) and `security-events: write` (SARIF upload); the workflow default is `contents: read`.

### Testing Requirements
- YAML can be parsed locally, but only a push exercises the pipeline. After pushing, read the run with `gh run list` / `gh run view <id> --log-failed`.

### Common Patterns
- `IMAGE_NAME` and `TRIVY_IMAGE` are workflow-level env vars reused across steps.

## Dependencies

### Internal
- Builds the root `Dockerfile`; runs `requirements-dev.txt`, `pyproject.toml` and `.flake8` settings.

### External
- `actions/checkout@v4`, `actions/setup-python@v5`, `docker/setup-buildx-action@v3`, `docker/metadata-action@v5`, `docker/build-push-action@v6`, `docker/login-action@v3`, `github/codeql-action/upload-sarif@v3`, Trivy image.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
