# syntax=docker/dockerfile:1.6

FROM python:3.11-slim AS builder
WORKDIR /build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1
COPY requirements.txt ./
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install -r requirements.txt

FROM python:3.11-slim AS runtime
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    REDSHIELD_AUDIT_DB=/data/audit.sqlite3
RUN groupadd --system redshield \
 && useradd --system --gid redshield --home /app --shell /usr/sbin/nologin redshield \
 && mkdir -p /app /data \
 && chown -R redshield:redshield /app /data
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=redshield:redshield app/ ./app/
COPY --chown=redshield:redshield eval/ ./eval/
COPY --chown=redshield:redshield main.py README.md ./
USER redshield
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3); sys.exit(0)" || exit 1
CMD ["uvicorn", "app.gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
