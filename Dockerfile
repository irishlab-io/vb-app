FROM docker.io/python:3.9

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV UV_COMPILE_BYTECODE=1
ENV VIRTUAL_ENV=/app/.venv

# Install PostgreSQL client
RUN apt-get update && apt-get install -y curl postgresql-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies only (no source code yet) — preserves Docker layer cache
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
RUN uv pip install --no-cache-dir httplib2==0.14.0 pycrypto==2.6.1 urllib3==1.24.3

# Copy remaining project files
COPY . .

# Install the project package and ensure uploads directory exists
RUN uv sync --frozen --no-dev \
    && mkdir -p src/vuln_bank/static/uploads \
    && chmod 777 src/vuln_bank/static/uploads

RUN chmod +x /app/start.sh

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:5000/healthz || exit 1

CMD ["./start.sh"]
