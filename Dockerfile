FROM docker.io/python:3.9-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV PYTHONUNBUFFERED=1

# Install PostgreSQL client
RUN apt-get update && apt-get install -y \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml uv.lock ./
# Install dependencies only (cached layer — rebuilds only when pyproject.toml/uv.lock change)
RUN uv sync --frozen --no-dev --no-install-project

# Copy source package and install it (separate layer for source changes)
COPY src/ ./src/
RUN uv sync --frozen --no-dev

# Copy remaining project files
COPY . .

# Ensure uploads directory exists and has proper permissions
RUN mkdir -p static/uploads && chmod 777 static/uploads
RUN chmod +x /app/start.sh

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import sys, urllib.request; sys.exit(0) if urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=5).getcode() == 200 else sys.exit(1)"

CMD ["./start.sh"]
