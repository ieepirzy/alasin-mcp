# SPDX-License-Identifier: Apache-2.0
# alasin-mcp: Streamable HTTP on :8000. Configuration is a TOML file named by
# ALASIN_CONFIG (default /etc/alasin/config.toml); see README.md.
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    ALASIN_CONFIG=/etc/alasin/config.toml

WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir uv==0.13.0 \
    && uv sync --locked --no-dev --extra origo \
    && useradd --system --uid 10001 --home-dir /var/lib/alasin alasin \
    && mkdir -p /var/lib/alasin/audit \
    && chown -R alasin /var/lib/alasin
USER alasin
# Work sessions, delegated tokens (encrypted) and audit files live here.
VOLUME ["/var/lib/alasin"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/app/.venv/bin/python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"]

CMD ["/app/.venv/bin/alasin-mcp"]
