# Installation Guide

This document covers all methods of running the Vulnerable Bank application, including environment configuration and common troubleshooting steps.

## Prerequisites

| Method | Requirements |
|---|---|
| Docker Compose (recommended) | Docker, Docker Compose v2, Git |
| Docker only | Docker, Git |
| Local | Python 3.9+, PostgreSQL 13+, [uv](https://docs.astral.sh/uv/), Git |

---

## Option 1: Docker Compose (Recommended)

```bash
git clone https://github.com/irishlab-io/vb-app.git
cd vb-app
docker compose up -d --build
```

The application will be available at `http://localhost:5000`.

### Services

The Compose stack starts three services:

| Service | Container | Description |
|---|---|---|
| `vb-app` | `vuln-app` | Flask application (port 5000 and 80) |
| `vb-db` | `vuln-db` | PostgreSQL 13 database (port 5432) |
| `vb-ai` | `vuln-ai` | Ollama local LLM inference server (port 11434) |

### Container Behaviour

- All three services use `restart: unless-stopped`, so Docker will restart them automatically on exit.
- The `vb-db` service exposes a health check (`pg_isready`). The `vb-app` service waits for PostgreSQL readiness before starting.
- The Flask development server runs with `debug=True`. This is intentional — it preserves training scenarios that target the Werkzeug debugger and should not be changed.
- A `GET /healthz` endpoint is exposed so the container can report whether the application and database are functional.
- Profile picture uploads are persisted via a bind mount to `./src/vuln_bank/static/uploads`.

### Loading the AI Model

The `vb-ai` service starts Ollama but does not pre-pull the model. Pull the model once after the stack is running:

```bash
docker exec -it vuln-ai ollama pull llama3.2
```

---

## Option 2: Docker Only

```bash
git clone https://github.com/irishlab-io/vb-app.git
cd vb-app
docker build -t vuln-bank .
docker run -p 5000:5000 vuln-bank
```

> **Note:** Running the application container without a PostgreSQL container requires an externally accessible PostgreSQL instance and appropriate `DB_*` environment variables passed to `docker run -e`.

---

## Option 3: Local Installation

### Steps

1. Clone the repository:

```bash
git clone https://github.com/irishlab-io/vb-app.git
cd vb-app
```

2. Install [uv](https://docs.astral.sh/uv/getting-started/installation/) if it is not already installed:

```bash
# Linux / macOS
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

3. Install project dependencies (uv creates and manages the virtual environment automatically):

```bash
uv sync
```

4. Copy the example environment file and adjust values for your local setup:

```bash
cp .env.example .env
```

Edit `.env` and change `DB_HOST` from `db` to `localhost` for a local PostgreSQL connection. See the [Environment Variables](#environment-variables) section for all available options.

5. Create the uploads directory:

```bash
# Linux / macOS
mkdir -p src/vuln_bank/static/uploads

# Windows
mkdir src\vuln_bank\static\uploads
```

6. Run the application:

```bash
uv run python -m vuln_bank.app
```

---

## Environment Variables

An `.env.example` file is provided at the repository root. Copy it to `.env` before running the application locally. The file is intentionally committed to simplify setup for educational environments — in any real-world project, environment files must not be committed to version control.

| Variable | Default | Description |
|---|---|---|
| `DB_NAME` | `vuln_bank` | PostgreSQL database name |
| `DB_USER` | `postgres` | PostgreSQL username |
| `DB_PASSWORD` | `postgres` | PostgreSQL password |
| `DB_HOST` | `db` | PostgreSQL host (`db` for Docker, `localhost` for local) |
| `DB_PORT` | `5432` | PostgreSQL port |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama API base URL |
| `OLLAMA_MODEL` | `llama3.2` | Ollama model name used by the AI agent |
| `CF_TUNNEL_TOKEN` | *(empty)* | Cloudflare Tunnel token (optional, for remote access) |

---

## Database Initialisation

The application uses PostgreSQL. On first run, the database schema is created automatically. The following tables are initialised:

- `users`
- `transactions`
- `loans`
- `virtual_cards`
- `card_transactions`
- `bill_categories`
- `billers`
- `bill_payments`

A default admin account (`admin` / `admin123`) is also created if it does not already exist. This credential is intentionally weak for training purposes.

---

## Running the Test Suite

The project uses [pytest](https://docs.pytest.org/) and [uv](https://docs.astral.sh/uv/) for dependency management. Run the full test suite with:

```bash
uv run pytest
```

Coverage reports are generated automatically under `tests/coverage/`. The minimum required coverage threshold is 60%.

To run a specific test file or marker:

```bash
# Run only unit tests
uv run pytest -m unit

# Run a specific file
uv run pytest tests/unit/test_auth.py
```

---

## Application Endpoints

| Path | Description |
|---|---|
| `http://localhost:5000` | Main application (web UI) |
| `http://localhost:5000/api/docs` | REST API documentation (Swagger UI) |
| `http://localhost:5000/graphql` | GraphQL analytics endpoint |
| `http://localhost:5000/healthz` | Health check |

---

## Troubleshooting

### Linux / macOS

**Permission denied when creating the uploads directory:**

```bash
sudo mkdir -p src/vuln_bank/static/uploads
sudo chown -R $USER:$USER src/vuln_bank/static/uploads
```

**Port 5000 already in use:**

```bash
sudo lsof -i:5000
sudo kill <PID>
```

---

### Windows

- If `uv` is not found after installation, open a new terminal session so the updated `PATH` is applied.
- For permission issues with the uploads folder, run the command prompt as Administrator.

---

### PostgreSQL

**Connection refused:**
- Ensure PostgreSQL is running.
- Verify credentials in the `.env` file.
- Check that the PostgreSQL port is not blocked by a firewall.

**Authentication failed:**
- Confirm that `DB_PASSWORD` in `.env` matches the password for the `postgres` user.
- To reset the password:

```sql
ALTER ROLE postgres WITH PASSWORD 'your_password';
```

**Installing PostgreSQL on Windows via Chocolatey:**

```powershell
choco install postgresql --version=17.4.0 -y
& 'C:\Program Files\PostgreSQL\17\bin\psql.exe' -U postgres -c "ALTER ROLE postgres WITH PASSWORD 'postgres';"
```

**Database does not exist:**

```sql
CREATE DATABASE vuln_bank;
```

Or using the command line:

```bash
createdb -U postgres -h localhost vuln_bank
```
