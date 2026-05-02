# Vulnerability Catalogue

This document lists all security vulnerabilities found in the Vulnerable Bank application, organised by file and function.

---

## `src/vuln_bank/auth.py`

### Module level

| CWE | Description |
|---|---|
| CWE-326 | Weak JWT secret key — `JWT_SECRET = "secret123"` |
| CWE-327 | Vulnerable algorithm list includes `"none"` — `ALGORITHMS = ["HS256", "none"]` |

### `generate_token()`

| CWE | Description |
|---|---|
| CWE-613 | No token expiration — the `exp` claim is never set, so tokens never expire |
| CWE-326 | Signing uses the weak hardcoded secret `"secret123"` |

### `verify_token()`

| CWE | Description |
|---|---|
| CWE-347 | Accepts the `"none"` algorithm, allowing unsigned tokens |
| CWE-295 | Falls back to signature-less decode on `InvalidSignatureError`, effectively bypassing signature verification |
| CWE-209 | Detailed exception messages written to the application log |

### `token_required()` decorator

| CWE | Description |
|---|---|
| CWE-522 | Token accepted from query parameters (`?token=`), form data, and cookies in addition to the `Authorization` header — increases the token-hijacking surface |
| CWE-613 | No expiration check is performed on decoded token payloads |
| CWE-209 | Exception detail included in the JSON error response (`"details": str(e)`) |

### `api_login()` — `POST /api/login`

| CWE | Description |
|---|---|
| CWE-89 | SQL injection — username and password are interpolated directly into the query string |
| CWE-200 | Response includes sensitive `debug_info` fields: login time, IP address, User-Agent |
| CWE-200 | `account_number` and `is_admin` flag returned to the caller on every login |

### `api_check_balance()` — `GET /api/check_balance`

| CWE | Description |
|---|---|
| CWE-862 | No object-level authorisation — any valid token can query any account balance |
| CWE-89 | `account_number` from query parameters is interpolated directly into the SQL query |

### `api_transfer()` — `POST /api/transfer`

| CWE | Description |
|---|---|
| CWE-20 | No input validation on `amount` — negative values and zero are accepted |
| CWE-362 | Race condition — balance is read then updated in separate, non-atomic statements |
| CWE-89 | `to_account` is interpolated directly into the `UPDATE` SQL statement |
| CWE-200 | Response discloses the recipient's new balance |

---

## `src/vuln_bank/app.py`

### Module level

| CWE | Description |
|---|---|
| CWE-798 | Hardcoded Flask secret key — `app.secret_key = "secret123"` |

### `generate_card_number()` / `generate_cvv()`

| CWE | Description |
|---|---|
| CWE-338 | Predictable card number and CVV generation using `random.choices` (not cryptographically secure) |

### `register()` — `POST /register`

| CWE | Description |
|---|---|
| CWE-915 | Mass assignment — all client-supplied JSON fields (including `is_admin`, `balance`) are passed directly to the `INSERT` query |
| CWE-200 | Response body contains `debug_data` including raw input, registered field list, and server User-Agent |
| CWE-200 | `X-Debug-Info` and `X-User-Info` response headers expose internal data |
| CWE-200 | Error response on duplicate username leaks a server-side timestamp |

### `login()` — `POST /login`

| CWE | Description |
|---|---|
| CWE-89 | SQL injection — username and password are interpolated into the query string |
| CWE-200 | Successful login response includes `debug_info` with user ID, account number, and admin flag |
| CWE-614 | Cookie set without the `Secure` flag |
| CWE-204 | Username enumeration — different error messages for unknown user vs. wrong password |

### `debug_users()` — `GET /debug/users`

| CWE | Description |
|---|---|
| CWE-200 | Unauthenticated endpoint returns all users including plaintext passwords and admin flags |

### `check_balance()` — `GET /check_balance/<account_number>`

| CWE | Description |
|---|---|
| CWE-862 | No authentication required — any caller can retrieve any account balance |
| CWE-89 | `account_number` from the URL path is interpolated into the SQL query |
| CWE-200 | Response returns username alongside balance |

### `transfer()` — `POST /transfer`

| CWE | Description |
|---|---|
| CWE-20 | No input validation on `amount` — negative values are accepted (the code checks `abs(amount)`) |
| CWE-362 | Race condition — balance check and debit are non-atomic |

### `get_transaction_history()` — `GET /transactions/<account_number>`

| CWE | Description |
|---|---|
| CWE-862 | No authentication required — full transaction history for any account is publicly accessible |
| CWE-89 | `account_number` is interpolated directly into the SQL query |
| CWE-200 | Error response includes the raw SQL query string and `server_time` |

### `upload_profile_picture()` — `POST /upload_profile_picture`

| CWE | Description |
|---|---|
| CWE-434 | No file type, content-type, or file size validation on uploads |
| CWE-22 | Path traversal — `secure_filename` is applied but the prefix is numeric only; crafted names may still escape the intended directory |
| CWE-200 | Success response discloses the full server-side file path |
| CWE-209 | Error response returns the exception message and file path |

### `upload_profile_picture_url()` — `POST /upload_profile_picture_url`

| CWE | Description |
|---|---|
| CWE-918 | SSRF — no URL scheme or host allowlist; the server fetches any URL supplied by the client |
| CWE-295 | TLS verification is disabled (`verify=False`) |
| CWE-200 | Response includes `debug_info` with the fetched URL, HTTP status, and content length |

### `update_bio()` — `POST /update_bio`

| CWE | Description |
|---|---|
| CWE-79 | Stored XSS — bio is stored and returned without any sanitisation |

### `request_loan()` — `POST /request_loan`

| CWE | Description |
|---|---|
| CWE-20 | No input validation on loan `amount` — negative values and zero are accepted |

### `approve_loan()` — `POST /admin/approve_loan/<loan_id>`

| CWE | Description |
|---|---|
| CWE-362 | Race condition — no check whether the loan is already approved before updating |
| CWE-20 | No validation on loan amount before crediting the user's balance |
| CWE-200 | Success response discloses full loan details and approver username |
| CWE-209 | Error response returns the raw exception string |

### `delete_account()` — `POST /admin/delete_account/<user_id>`

| CWE | Description |
|---|---|
| CWE-778 | No audit logging of the deletion event |
| CWE-200 | Response discloses which admin performed the deletion and the timestamp |

### `create_admin()` — `POST /admin/create_admin`

| CWE | Description |
|---|---|
| CWE-89 | SQL injection — username, password, and account number are interpolated into the `INSERT` query |
| CWE-521 | No password complexity requirements enforced |

### `forgot_password()` / `api_v1_forgot_password()` / `api_v2_forgot_password()` / `api_v3_forgot_password()`

| CWE | Description |
|---|---|
| CWE-89 | SQL injection — username is interpolated into the `SELECT` query |
| CWE-330 | Weak reset PIN — only 3 digits (v1/v2) or 4 digits (v3), trivially brute-forceable |
| CWE-312 | Reset PIN stored in plaintext in the database |
| CWE-200 | v1 response includes the plaintext PIN in `debug_info` |
| CWE-204 | Username enumeration — distinct error returned when username is not found |

### `reset_password()` / `api_v1_reset_password()` / `api_v2_reset_password()` / `api_v3_reset_password()`

| CWE | Description |
|---|---|
| CWE-307 | No rate limiting on PIN attempts — brute force is unrestricted |
| CWE-208 | Timing attack possible in PIN verification |
| CWE-521 | No password complexity requirements on new password |
| CWE-204 | Username enumeration — distinct error returned for invalid PIN |
| CWE-200 | v1 error response includes the attempted PIN |
| CWE-209 | Detailed exception string returned in error responses |

### `api_v3_get_user()` — `GET /api/v3/user/<user_id>`

| CWE | Description |
|---|---|
| CWE-639 | IDOR — no authorisation check; any authenticated user can retrieve any other user's details by ID |

### `api_transactions()` — `GET /api/transactions`

| CWE | Description |
|---|---|
| CWE-89 | SQL injection — `account_number` from query parameters is interpolated into the query string |

### `create_virtual_card()` — `POST /api/virtual-cards/create`

| CWE | Description |
|---|---|
| CWE-20 | No validation on card limit value |
| CWE-89 | SQL injection — `card_type` from request body is interpolated into the `INSERT` query |
| CWE-200 | Full card details (number, CVV, expiry) returned in the creation response |

### `get_virtual_cards()` — `GET /api/virtual-cards`

| CWE | Description |
|---|---|
| CWE-200 | Full CVV and card number included in every list response with no masking |

### `toggle_card_freeze()` — `POST /api/virtual-cards/<card_id>/toggle-freeze`

| CWE | Description |
|---|---|
| CWE-352 | No CSRF protection |
| CWE-639 | BOLA — no check that the card belongs to the requesting user |
| CWE-89 | `card_id` from the URL is interpolated directly into the SQL query |

### `get_card_transactions()` — `GET /api/virtual-cards/<card_id>/transactions`

| CWE | Description |
|---|---|
| CWE-639 | BOLA — no check that the card belongs to the requesting user |
| CWE-89 | `card_id` from the URL is interpolated directly into the SQL query |

### `update_card_limit()` — `POST /api/virtual-cards/<card_id>/update-limit`

| CWE | Description |
|---|---|
| CWE-915 | Mass assignment — all client-supplied fields (including `current_balance`, `is_frozen`) are applied to the card record |
| CWE-89 | Field names from the request body are interpolated into the `SET` clause without a whitelist |
| CWE-639 | BOLA — no check that the card belongs to the requesting user |
| CWE-200 | Response includes all updated field names and current card state |

### `fund_virtual_card()` — `POST /api/virtual-cards/<card_id>/fund`

| CWE | Description |
|---|---|
| CWE-915 | Mass assignment — client can override the `exchange_rate` field, controlling the currency conversion |

### `get_bill_categories()` — `GET /api/bill-categories`

| CWE | Description |
|---|---|
| CWE-862 | No authentication required |

### `get_billers_by_category()` — `GET /api/billers/by-category/<category_id>`

| CWE | Description |
|---|---|
| CWE-89 | SQL injection — `category_id` from the URL is interpolated into the query |
| CWE-200 | Biller account numbers disclosed in the response |

### `create_bill_payment()` — `POST /api/bill-payments/create`

| CWE | Description |
|---|---|
| CWE-20 | No input validation on payment amount or payment method |
| CWE-639 | BOLA — no check that the virtual card belongs to the requesting user |
| CWE-89 | `payer` and `biller` queries built with interpolated user ID and biller ID |
| CWE-362 | Race condition between balance read and debit |
| CWE-340 | Predictable reference numbers — `BILL{int(time.time())}` |

### `get_payment_history()` — `GET /api/bill-payments/history`

| CWE | Description |
|---|---|
| CWE-89 | SQL injection — `user_id` from the token is interpolated into the query |
| CWE-200 | Excessive data exposure — full card number and internal IDs included in each payment record |

### `ai_chat_authenticated()` — `POST /api/ai/chat`

| CWE | Description |
|---|---|
| CWE-77 | Prompt injection — raw user input is concatenated into the LLM prompt |
| CWE-200 | Sensitive user context (account number, balance, admin status) included in every LLM request |
| CWE-209 | Error response exposes AI system information |

### `ai_chat_anonymous()` — `POST /api/ai/chat/anonymous`

| CWE | Description |
|---|---|
| CWE-862 | No authentication required |
| CWE-77 | Prompt injection — raw user input passed to the LLM |

### `ai_system_info()` — `GET /api/ai/system-info`

| CWE | Description |
|---|---|
| CWE-200 | Unauthenticated endpoint exposes the AI model name, API URL, full system prompt, and known attack vectors |

---

## `src/vuln_bank/ai_agent_deepseek.py`

### `VulnerableAIAgent` class / `__init__()`

| CWE | Description |
|---|---|
| CWE-200 | System prompt is overly permissive and explicitly instructs the LLM to follow adversarial instructions |
| CWE-200 | System prompt is exposed via `get_system_info()` without authentication |

### `chat()`

| CWE | Description |
|---|---|
| CWE-200 | Sensitive user context (ID, account number, balance, admin flag) embedded directly in the LLM prompt |
| CWE-200 | Database query results appended to the prompt and forwarded to the external DeepSeek API |
| CWE-77 | User message appended to the prompt without any sanitisation or injection protection |
| CWE-209 | Exception handler returns API key status, model name, and system info in the error response |

### `_should_include_database_info()` / `_is_prompt_injection_request()`

| CWE | Description |
|---|---|
| CWE-20 | Keyword-based injection detection is trivially bypassed by rewording or using synonyms |

### `_get_database_context()`

| CWE | Description |
|---|---|
| CWE-200 | All user records (including account numbers and balances) queried and included in the LLM context |
| CWE-200 | Full database schema exposed when schema-related keywords appear in the message |
| CWE-200 | Recent transaction history for any account included based on keyword matching |
| CWE-862 | No authorisation check — data for any user is fetched based solely on message content |

### `_call_deepseek_api()`

| CWE | Description |
|---|---|
| CWE-209 | API HTTP errors (status code and full response body) returned to the caller |
| CWE-209 | Network exceptions expose internal connection details |

### `get_system_info()`

| CWE | Description |
|---|---|
| CWE-200 | Returns model name, API provider, API URL, full system prompt, and list of known vulnerabilities — without authentication |

---

## `src/vuln_bank/transaction_graphql.py`

### `_load_user_actor()` / `_load_actor_by_account_number()` / `_load_transactions()` / `_load_lending_and_bill_metrics()`

| CWE | Description |
|---|---|
| CWE-89 | SQL injection — `user_id` and `account_number` values are interpolated directly into query strings rather than passed as parameterised arguments |

---

## Summary by CWE

| CWE | Title | Count |
|---|---|---|
| CWE-20 | Improper Input Validation | 8 |
| CWE-77 | Improper Neutralisation of Special Elements (Prompt Injection) | 3 |
| CWE-79 | Cross-Site Scripting (XSS) | 1 |
| CWE-89 | SQL Injection | 18 |
| CWE-200 | Information Exposure | 25 |
| CWE-204 | Response Discrepancy (User Enumeration) | 4 |
| CWE-208 | Timing Discrepancy (Timing Attack) | 1 |
| CWE-209 | Error Message Information Exposure | 10 |
| CWE-295 | Improper Certificate Validation | 2 |
| CWE-307 | Improper Restriction of Excessive Authentication Attempts | 1 |
| CWE-312 | Cleartext Storage of Sensitive Information | 1 |
| CWE-326 | Inadequate Encryption Strength (Weak Key) | 2 |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm | 1 |
| CWE-330 | Use of Insufficiently Random Values (Weak PIN) | 1 |
| CWE-338 | Use of Cryptographically Weak PRNG | 1 |
| CWE-340 | Generation of Predictable Numbers | 1 |
| CWE-347 | Improper Verification of Cryptographic Signature | 1 |
| CWE-352 | Cross-Site Request Forgery (CSRF) | 1 |
| CWE-362 | Race Condition | 5 |
| CWE-434 | Unrestricted Upload of File with Dangerous Type | 1 |
| CWE-521 | Weak Password Requirements | 2 |
| CWE-522 | Insufficiently Protected Credentials (Token in URL) | 1 |
| CWE-613 | Insufficient Session Expiration | 2 |
| CWE-614 | Sensitive Cookie Without Secure Attribute | 1 |
| CWE-639 | Authorisation Bypass Through User-Controlled Key (BOLA/IDOR) | 6 |
| CWE-778 | Insufficient Logging | 1 |
| CWE-798 | Use of Hard-coded Credentials | 1 |
| CWE-862 | Missing Authorisation | 5 |
| CWE-915 | Mass Assignment | 3 |
| CWE-918 | Server-Side Request Forgery (SSRF) | 1 |
