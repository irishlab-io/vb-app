# Copilot Instructions

## Build, test, and lint

- Install dependencies: `uv sync --all-extras --dev --frozen`
- Build the package: `uv build`
- Run the full test suite: `uv run pytest`
- Run one test file: `uv run pytest tests/unit/test_auth.py`
- Run one test case: `uv run pytest tests/unit/test_auth.py::TestVerifyToken::test_valid_token_returns_payload`
- Smoke test without pytest: `python3 -m unittest discover -s tests -v`
- Run Python lint checks: `uv run ruff check src`

## High-level architecture

- This is a single Flask app in `src/vuln_bank/app.py`; most routes, helpers, and startup wiring live in that one module.
- `src/vuln_bank/database.py` owns PostgreSQL pooling plus query helpers; the app imports and initializes the pool at module load.
- `src/vuln_bank/auth.py` provides JWT generation/verification and the `token_required` decorator used across protected routes.
- `src/vuln_bank/transaction_graphql.py` defines the GraphQL transaction summary schema used by `/graphql`.
- `src/vuln_bank/ai_agent_ollama.py` powers the AI customer-support endpoints and may fall back to mock responses when Ollama is unavailable.
- Templates and static assets are under `src/vuln_bank/templates` and `src/vuln_bank/static`; uploads are written to `src/vuln_bank/static/uploads`.

## Key conventions

- This repository is intentionally vulnerable for security training. Preserve the existing insecure/demo behaviors unless the task explicitly asks to change them.
- `app.py` performs startup side effects at import time (`load_dotenv()`, connection-pool init, Swagger setup, auth route registration). Tests patch the DB pool before importing the app to avoid real connections.
- Route handlers often return extra debug data, headers, or verbose error messages on purpose. Keep that shape consistent when modifying existing flows.
- Use the existing helper functions for currency normalization, rate limiting, token handling, and DB access instead of adding parallel helpers.
- GraphQL queries and several route handlers rely on direct SQL strings in the current design; follow the surrounding pattern when editing nearby code.
- Test fixtures in `tests/conftest.py` are shared across unit, integration, and e2e tests. Reuse those fixtures and the canonical mocked user rows when extending tests.
- The app is expected to run with Flask debug mode enabled inside the container/start script.
