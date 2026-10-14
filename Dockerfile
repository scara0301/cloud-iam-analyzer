# syntax=docker/dockerfile:1

# ---- Stage 1: build dependencies into an isolated virtualenv ----
FROM python:3.11-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /build
COPY requirements.txt .
RUN pip install -r requirements.txt \
    && pip uninstall -y setuptools wheel

# ---- Stage 2: slim runtime, no build tooling, non-root ----
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# The base image ships setuptools/wheel (and their vendored deps), which the app never
# uses at runtime but which carry HIGH CVEs; drop them to keep the Trivy gate clean.
# Fixed numeric UID so Kubernetes `runAsNonRoot` can verify it.
RUN /usr/local/bin/python -m pip uninstall -y setuptools wheel \
    && useradd --create-home --uid 10001 appuser

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=10001:10001 app.py ./
COPY --chown=10001:10001 iam_analyzer ./iam_analyzer

USER 10001
EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=3)"

ENTRYPOINT ["streamlit", "run", "app.py", \
    "--server.port=8501", \
    "--server.address=0.0.0.0", \
    "--server.headless=true", \
    "--browser.gatherUsageStats=false"]
