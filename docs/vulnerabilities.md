# Vulnerability Catalogue

This document lists all intentional security vulnerabilities implemented in the Vulnerable Bank application, organised by category. Each vulnerability is present by design and is intended to serve as a training target.

---

## 1. Authentication and Authorisation

- SQL injection in the login endpoint
- Weak JWT implementation
- Broken Object Level Authorisation (BOLA)
- Broken Object Property Level Authorisation (BOPLA)
- Mass assignment and excessive data exposure
- Weak password reset mechanism (3-digit PIN, brute-forceable)
- JWT token stored in `localStorage`
- No server-side token invalidation on logout
- No session expiration

---

## 2. Data Security

- Information disclosure in API responses
- Sensitive data exposure
- Plaintext password storage in the database
- SQL injection points across multiple endpoints
- Debug information exposed in error responses
- Detailed error messages returned to the client

---

## 3. Transactions

- No validation on transfer amounts
- Negative amount transfers permitted
- No transaction limits enforced
- Race conditions in transfer and balance update operations
- Transaction history accessible without proper authorisation
- No validation on recipient account existence

---

## 4. File Operations

- Unrestricted file upload (no type or size validation)
- Path traversal vulnerabilities
- Directory traversal
- Unsafe file naming (user-controlled filenames)
- Server-Side Request Forgery (SSRF) via the URL-based profile image import endpoint (`/upload_profile_picture_url`)

---

## 5. Session Management

- Weak JWT secret keys
- No session expiration
- Token exposure in URLs
- Token vulnerabilities from weak signing

---

## 6. Client and Server-Side Flaws

- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Insecure direct object references
- No rate limiting on any endpoint

---

## 7. Virtual Cards

- Mass assignment in card limit update endpoint
- Mass assignment in card funding — client-controlled `exchange_rate` field
- Predictable card number generation
- Plaintext storage of card details in the database
- No validation on card limits
- BOLA in card read and write operations
- Race conditions in balance update operations
- Card detail information disclosure
- No transaction verification
- No card activity monitoring
- Client-controlled currency conversion rate during card funding

---

## 8. Bill Payments

- No validation on payment amounts
- SQL injection in biller query construction
- Information disclosure in payment history
- Predictable payment reference numbers
- Transaction history exposed without authorisation checks
- No validation on biller account existence
- Race conditions in payment processing
- BOLA in payment history access
- No payment limits enforced

---

## 9. AI Customer Support Agent

The AI agent uses the DeepSeek API (with a mock fallback) and is configured with an intentionally permissive system prompt and direct database access.

| CWE | Vulnerability |
|---|---|
| CWE-77 | Prompt Injection |
| CWE-200 | AI-based Information Disclosure |
| CWE-862 | Broken Authorisation in AI context |
| CWE-209 | AI System Information Exposure |
| CWE-20 | Insufficient Input Validation for AI prompts |

Additional weaknesses:

- Direct database access through AI manipulation
- AI role override attacks
- Context injection
- AI-assisted unauthorised data access
- Exposed AI system prompts and configuration details

---

## 10. GraphQL

- Schema introspection enabled on the `/graphql` endpoint
- Weak JWT authentication inherited by the GraphQL endpoint
- SQL injection in GraphQL resolver query construction (e.g. via the `accountNumber` argument)
- No query depth or complexity controls
- Raw GraphQL error messages exposed to the client
- Transaction analytics accessible via admin-scoped queries without sufficient access control
