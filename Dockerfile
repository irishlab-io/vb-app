FROM docker.io/python:3.9-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV PYTHONUNBUFFERED=1

# Install PostgreSQL client
RUN apt-get update && apt-get install -y \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies only (no source code yet) — preserves Docker layer cache
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy remaining project files
COPY . .

# Install the project package and ensure uploads directory exists
RUN uv sync --frozen --no-dev \
    && mkdir -p src/vuln_bank/static/uploads \
    && chmod 777 src/vuln_bank/static/uploads

RUN chmod +x /app/start.sh

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import sys, urllib.request; sys.exit(0) if urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=5).getcode() == 200 else sys.exit(1)"

CMD ["./start.sh"]
