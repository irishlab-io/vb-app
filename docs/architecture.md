# Architecture Overview

This document describes the high-level architecture of the Vulnerable Bank application, including its modules, database schema, request lifecycle, and intentional design decisions.

---

## High-Level Design

Vulnerable Bank is a monolithic Flask web application backed by a PostgreSQL database. It exposes three types of interfaces:

1. **Web UI** — server-rendered HTML pages using Jinja2 templates.
2. **REST API** — JSON endpoints under `/api/` used by the frontend and for direct API testing.
3. **GraphQL API** — a single endpoint at `/graphql` used by the analytics dashboard.

An optional local AI inference layer powered by [Ollama](https://ollama.com/) provides an AI customer support agent that demonstrates LLM-specific vulnerabilities.

```
┌─────────────────────────────────────┐
│           Browser / API Client       │
└───────────────────┬─────────────────┘
                    │ HTTP
         ┌──────────▼──────────┐
         │     Flask App        │
         │  (vuln_bank.app)     │
         │                     │
         │  ┌───────────────┐  │
         │  │  REST routes  │  │
         │  └───────────────┘  │
         │  ┌───────────────┐  │
         │  │ GraphQL route │  │
         │  └───────────────┘  │
         │  ┌───────────────┐  │
         │  │  Web UI routes│  │
         │  └───────────────┘  │
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐     ┌─────────────────┐
         │   PostgreSQL (DB)    │     │  Ollama (LLM)    │
         │   vuln_bank schema   │     │  llama3.2 model  │
         └─────────────────────┘     └─────────────────┘
```

---

## Module Responsibilities

### `src/vuln_bank/app.py`

The main application module. It:

- Creates and configures the Flask `app` instance.
- Calls `init_connection_pool()` at import time to establish the PostgreSQL connection pool.
- Registers the Swagger UI blueprint at `/api/docs`.
- Registers all web UI and REST API routes via `init_auth_routes(app)` (at import time) and additional `init_*_routes` functions called from `main()`.
- Defines helper utilities: card currency conversion, in-memory rate limiting, and the AI rate-limit decorator.
- Provides the application entry point in `main()`.

Because the connection pool and route registration happen at **module import time**, tests must patch `psycopg2.pool.SimpleConnectionPool` before importing `vuln_bank.app`. See `tests/conftest.py` for the required setup.

### `src/vuln_bank/auth.py`

Handles JWT-based authentication:

- `generate_token(user_id, username, is_admin)` — creates a signed HS256 JWT.
- `verify_token(token)` — decodes and validates a token. Falls back to signatureless decoding on `InvalidSignatureError` (intentional vulnerability).
- `token_required` — Flask decorator that extracts the token from the `Authorization` header, query parameters, form data, or cookies.
- `init_auth_routes(app)` — registers `/api/login`, `/api/check_balance`, and `/api/transfer`.

### `src/vuln_bank/database.py`

Manages the PostgreSQL connection lifecycle:

- `init_connection_pool()` — creates a `psycopg2.pool.SimpleConnectionPool` with retry logic. Called once at application startup.
- `init_db()` — creates all tables and inserts seed data (default admin account, bill categories, billers). Safe to call on an already-initialised database.
- `execute_query(query, params, fetch)` — executes a single query and returns results if `fetch=True`.
- `execute_transaction(queries_and_params)` — runs multiple queries atomically.
- `check_database_connection()` — performs a `SELECT 1` health check used by the `/healthz` endpoint.

### `src/vuln_bank/transaction_graphql.py`

Implements the GraphQL API using [Graphene](https://graphene-python.org/):

- Exposes a `TransactionSummary` query that returns aggregated transaction analytics.
- Resolvers load data from the database using `execute_query`.
- The schema is exported as `transaction_graphql_schema` and mounted in `app.py` at `/graphql`.

### `src/vuln_bank/ai_agent_ollama.py`

Implements the AI customer support agent:

- `VulnerableAIAgent` — wraps the Ollama `/api/chat` endpoint.
- `chat(user_message, user_context)` — builds a prompt that includes optional user context and database query results, then calls Ollama.
- `_call_ollama_api(prompt)` — calls Ollama; falls back to `_generate_mock_response()` if Ollama is unreachable.
- `get_system_info()` — returns model name, API URL, and the full system prompt (intentionally exposed without authentication).

A module-level singleton `ai_agent` is created at import time and used by the routes registered in `app.py`.

### `src/vuln_bank/site_config.py`

Centralises author and repository metadata that is injected into all Jinja2 templates via the `inject_site_config` context processor in `app.py`.

---

## Database Schema

```
users
├── id              SERIAL PRIMARY KEY
├── username        TEXT NOT NULL UNIQUE
├── password        TEXT NOT NULL          -- stored in plaintext (intentional)
├── account_number  TEXT NOT NULL UNIQUE
├── balance         DECIMAL(15,2)
├── is_admin        BOOLEAN
├── profile_picture TEXT
├── reset_pin       TEXT                   -- stored in plaintext (intentional)
├── bio             TEXT
└── is_suspended    BOOLEAN

transactions
├── id               SERIAL PRIMARY KEY
├── from_account     TEXT NOT NULL
├── to_account       TEXT NOT NULL
├── amount           DECIMAL(15,2) NOT NULL
├── timestamp        TIMESTAMP
├── transaction_type TEXT NOT NULL
└── description      TEXT

loans
├── id      SERIAL PRIMARY KEY
├── user_id INTEGER → users.id
├── amount  DECIMAL(15,2)
└── status  TEXT ('pending' | 'approved' | 'rejected')

virtual_cards
├── id              SERIAL PRIMARY KEY
├── user_id         INTEGER → users.id
├── card_number     TEXT NOT NULL UNIQUE
├── cvv             TEXT NOT NULL
├── expiry_date     TEXT NOT NULL
├── card_limit      NUMERIC(20,8)
├── current_balance NUMERIC(20,8)
├── is_frozen       BOOLEAN
├── is_active       BOOLEAN
├── created_at      TIMESTAMP
├── last_used_at    TIMESTAMP
├── card_type       TEXT
└── currency        TEXT

card_transactions
├── id               SERIAL PRIMARY KEY
├── card_id          INTEGER → virtual_cards.id
├── amount           NUMERIC(20,8) NOT NULL
├── merchant_name    TEXT
├── transaction_type TEXT NOT NULL
├── status           TEXT
├── timestamp        TIMESTAMP
└── description      TEXT

bill_categories
├── id          SERIAL PRIMARY KEY
├── name        TEXT NOT NULL UNIQUE
├── description TEXT
└── is_active   BOOLEAN

billers
├── id             SERIAL PRIMARY KEY
├── category_id    INTEGER → bill_categories.id
├── name           TEXT NOT NULL
├── account_number TEXT NOT NULL
├── description    TEXT
├── minimum_amount DECIMAL(15,2)
├── maximum_amount DECIMAL(15,2)
└── is_active      BOOLEAN

bill_payments
├── id             SERIAL PRIMARY KEY
├── user_id        INTEGER → users.id
├── biller_id      INTEGER → billers.id
├── amount         DECIMAL(15,2) NOT NULL
├── payment_method TEXT ('balance' | 'virtual_card')
├── card_id        INTEGER → virtual_cards.id  -- NULL when paid with balance
├── reference_number TEXT
├── status         TEXT
├── created_at     TIMESTAMP
├── processed_at   TIMESTAMP
└── description    TEXT
```

---

## Request Lifecycle

### Web UI Request

```
Browser → Flask route (app.py)
         → execute_query / execute_transaction (database.py)
         → render_template (Jinja2)
         → HTML response
```

### REST API Request (authenticated)

```
Client → Flask route
       → @token_required (auth.py)
           → verify_token → jwt.decode
       → route handler
           → execute_query (database.py)
       → jsonify → JSON response
```

### GraphQL Request

```
Client → POST /graphql (app.py)
       → @token_required
       → graphql_query_handler
           → transaction_graphql_schema.execute (transaction_graphql.py)
               → _load_* resolver functions
                   → execute_query (database.py)
       → JSON response
```

### AI Chat Request

```
Client → POST /api/ai/chat (app.py)
       → @ai_rate_limit
       → @token_required (authenticated endpoint)
       → ai_agent.chat(message, user_context)
           → _should_include_database_info / _is_prompt_injection_request
           → _get_database_context (execute_query)
           → _call_ollama_api → Ollama HTTP API
               → fallback: _generate_mock_response (if Ollama unreachable)
       → JSON response
```

---

## Key Design Decisions

### Intentional Vulnerabilities

Every security weakness in the application is present by design. The vulnerabilities are documented exhaustively in [docs/vulnerabilities.md](vulnerabilities.md). Do **not** fix them — their presence is the educational value of the project.

### Flask Debug Mode

The application runs with `debug=True` in all environments. This is intentional: the Werkzeug interactive debugger is itself a training scenario (remote code execution via the debug console). The `start.sh` entrypoint and Dockerfile both preserve this setting.

### In-Memory Rate Limiting

The AI endpoints use a simple in-memory dictionary (`rate_limit_storage` in `app.py`) keyed by user ID or IP address. This state is not shared between worker processes or container restarts. The rate limiter is intentionally simple and bypassable, which is consistent with the educational goals of the project.

### Connection Pooling

`psycopg2.pool.SimpleConnectionPool` is used with a pool size of 2–30 connections. The pool is initialised once at module import time and reused across all requests. Tests patch the pool constructor to avoid requiring a live database.

### Virtual Card Currencies

The application supports eight currencies (USD, GBP, NGN, JPY, EUR, QAR, BTC, ETH) with fixed conversion rates defined in `CARD_CURRENCY_RATES` in `app.py`. Rates are hardcoded and not fetched from an external source.
