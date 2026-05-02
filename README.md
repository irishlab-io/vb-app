# Vuln Bank

A deliberately vulnerable web application for security education. It is designed for practicing application security testing across web, REST APIs, GraphQL, and large language models (LLMs), as well as secure code review and DevSecOps pipeline implementation.

> **Warning:** This application contains intentional security vulnerabilities. It must only be run in isolated, non-production environments and must never be exposed to public networks or used with real personal data.

## Overview

Vuln Bank simulates a retail banking platform with a range of realistic features, each containing deliberately introduced security weaknesses. It is intended for security engineers, developers, QA analysts, and DevSecOps practitioners who want hands-on experience with:

- Common web application and API vulnerability classes
- AI and LLM-specific attack vectors
- Secure coding practices and remediation
- Security testing automation
- DevSecOps toolchain integration

## Application Features

The application includes the following functional areas, each of which contains associated vulnerabilities:

- User authentication and authorisation
- Account balance management
- Money transfers
- Loan requests
- Profile picture upload (direct and URL-based)
- Transaction history and analytics (GraphQL-backed dashboard)
- Password reset via 3-digit PIN
- Multi-currency virtual card management with currency conversion (USD, GBP, NGN, JPY, EUR, QAR, BTC, ETH)
- Bill payments
- AI customer support agent (DeepSeek API or mock mode)

For a full breakdown of implemented vulnerabilities by category, see [docs/vulnerabilities.md](docs/vulnerabilities.md).

## Quick Start

The recommended way to run the application is via Docker Compose.

```bash
git clone https://github.com/irishlab-io/vuln-bank.git
cd vuln-bank
docker-compose up -d --build
```

The application will be available at `http://localhost:5000`.

For detailed installation instructions, including local setup, environment configuration, and troubleshooting, see [docs/installation.md](docs/installation.md).

## Attribution

This project was originally created by [Commando-X](https://github.com/Commando-X) and he still maintains it. Although I required to improve and evolve this project faster than it was possible for us to collaborate. Eventually I will attempt to merge my improvement toward his repository.

## Disclaimer

This application contains intentional security vulnerabilities for educational purposes only. Do not deploy it in production, run it on public networks, use it with real personal data, or use it for any malicious purpose.

## License

This project is licensed under the MIT License. See the [LICENSE.md](LICENSE.md) file for details.
