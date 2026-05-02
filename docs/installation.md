# Installation Guide

This document covers all methods of running the Vulnerable Bank application, including environment configuration and common troubleshooting steps.

## Prerequisites

| Method | Requirements |
|---|---|
| Docker Compose (recommended) | Docker, Docker Compose, Git |
| Docker only | Docker, Git |
| Local | Python 3.9+, PostgreSQL, pip, Git |

---

## Option 1: Docker Compose (Recommended)

```bash
git clone https://github.com/irishlab-io/vuln-bank.git
cd vuln-bank
docker-compose up -d --build
```

The application will be available at `http://localhost:5000`.

### Container Behaviour

- Both `web` and `db` services use `restart: unless-stopped`, so Docker will restart them automatically on exit.
- The `db` service exposes a health check. The `web` service waits for PostgreSQL readiness before starting.
- The Flask development server runs with `debug=True`. This is intentional — it preserves training scenarios that target the Werkzeug debugger and should not be changed.
- A `GET /healthz` endpoint is exposed so the container can report whether the application and database are functional.

---

## Option 2: Docker Only

```bash
git clone https://github.com/irishlab-io/vuln-bank.git
cd vuln-bank
docker build -t vuln-bank .
docker run -p 5000:5000 vuln-bank
```

---

## Option 3: Local Installation

### Steps

1. Clone the repository:

```bash
git clone https://github.com/irishlab-io/vuln-bank.git
cd vuln-bank
```

2. Create and activate a virtual environment:

```bash
# Linux / macOS
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Create the uploads directory:

```bash
# Linux / macOS
mkdir -p static/uploads

# Windows
mkdir static\uploads
```

5. Update the `.env` file — change `DB_HOST` from `db` to `localhost` for a local PostgreSQL connection.

6. Run the application:

```bash
# Linux / macOS
python3 app.py

# Windows
python app.py
```

---

## Environment Variables

The `.env` file is intentionally committed to this repository to simplify setup for educational environments. In any real-world project, environment files must not be committed to version control.

```bash
DB_NAME=vulnerable_bank
DB_USER=postgres
DB_PASSWORD=postgres
DB_HOST=db         # Change to 'localhost' for local installation
DB_PORT=5432
```

---

## Database Initialisation

The application uses PostgreSQL. On first run, the database is initialised automatically and the following tables are created:

- `users`
- `transactions`
- `loans`

---

## Smoke Test

To validate the local runtime without starting containers:

```bash
python3 -m unittest discover -s tests -v
```

This checks the `/healthz` endpoint and verifies that `start.sh` waits for the database before launching the Flask application. If Flask dependencies are not installed in the current environment, the `/healthz` route test is skipped and the startup script test still runs.

---

## Application Endpoints

| Path | Description |
|---|---|
| `http://localhost:5000` | Main application |
| `http://localhost:5000/api/docs` | REST API documentation |
| `http://localhost:5000/graphql` | GraphQL analytics endpoint |
| `http://localhost:5000/healthz` | Health check |

---

## Troubleshooting

### Linux / macOS

**Permission denied when creating directories:**

```bash
sudo mkdir -p static/uploads
sudo chown -R $USER:$USER static/uploads
```

**Port 5000 already in use:**

```bash
sudo lsof -i:5000
sudo kill <PID>
```

---

### Windows

- If `python` is not found, ensure Python is on the system PATH or use `py` instead.
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
CREATE DATABASE vulnerable_bank;
```

Or using the command line:

```bash
createdb -U postgres -h localhost vulnerable_bank
```
