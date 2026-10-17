<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-10-17 | Updated: 2026-10-17 -->

# .devcontainer

## Purpose
Configuration for a reproducible VS Code development container (Python 3.11 with Docker and kubectl
tooling), matching the version CI and the production image use. Not yet opened or tested.

## Key Files
| File | Description |
|------|-------------|
| `devcontainer.json` | Base image `mcr.microsoft.com/devcontainers/python:1-3.11-bookworm`; features for Docker-outside-of-Docker and kubectl; `postCreateCommand` installs `requirements-dev.txt`; forwards port 8501; recommends Python, black, flake8, Docker and Kubernetes extensions; format-on-save with black |

## Subdirectories
None.

## For AI Agents

### Working In This Directory
- Keep the Python version in sync with the `Dockerfile` and CI (`3.11`).
- Docker-outside-of-Docker reuses the host Docker daemon (Docker Desktop with WSL2 on Windows).

### Testing Requirements
- Open the repo in VS Code, run "Reopen in Container", then `pytest` inside it.

## Dependencies

### Internal
- `requirements-dev.txt` (installed on creation).

### External
- VS Code Dev Containers extension, Docker Desktop.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
