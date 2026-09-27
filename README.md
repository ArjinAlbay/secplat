# SecPlat 🛡️

[![Python](https://img.shields.io/badge/Python-3.13-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-16-000000?style=flat-square&logo=next.js&logoColor=white)](https://nextjs.org)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![Celery](https://img.shields.io/badge/Celery-5.4+-37814A?style=flat-square&logo=celery&logoColor=white)](https://docs.celeryq.dev)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-18.6-4169E1?style=flat-square&logo=postgresql&logoColor=white)](https://postgresql.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

**SecPlat** is an open-source, next-generation **Application Security Posture Management (ASPM)** and automated security orchestration platform. It unifies DAST, SAST, SCA, Secret Detection, IaC, and Recon tools into an enterprise-grade scan orchestration engine with unified deduplication, security posture scoring, and real-time interactive dashboards.

---

## 🌟 Key Features

- 🎯 **Unified Multi-Tool Security Engine**:
  - **DAST (Nuclei)**: Dynamic application and network vulnerability scanner with templated exploits.
  - **Recon (Subfinder & HTTPx)**: Automated subdomain enumeration, active web probe, and live service discovery.
  - **SAST (Semgrep)**: Semantic static code analysis and custom rule enforcement.
  - **SCA & Containers (Trivy)**: Software composition analysis, CVE detection, container image vulnerabilities.
  - **Secrets (Gitleaks)**: Fast, regex & entropy-based secret detection across git repositories and source trees.
  - **IaC Security (Checkov)**: Infrastructure as Code policy auditing for Terraform, Kubernetes, and Dockerfile.
- 🚀 **Automated Pipelines & Chained Workflows**:
  - **External Recon Pipeline**: `Subfinder` $\rightarrow$ `HTTPx` $\rightarrow$ `Nuclei` automated workflow.
  - **Full Codebase Audit**: Multi-scanner orchestration (`Gitleaks` + `Semgrep` + `Trivy` + `Checkov`) generating a unified **0–100 Security Score** with A–F grading.
- 🧠 **Domain-Driven Architecture (DDD)**: Clean architecture adhering strictly to `presentation > infrastructure > application > domain` layers enforced by `import-linter`.
- ⚡ **Reliable Async Processing**: Outbox pattern for scan lifecycle management with Celery workers, Redis message brokers, and periodic watchdog reconcilers.
- 📊 **Modern Web Console**: Next.js 16 + React 19 UI with real-time scan monitors, vulnerability detail drawers, severity filters, and executive PDF/HTML report exports.

---

## 🏗️ Architecture Overview

```
                          ┌─────────────────────────────┐
                          │   SecPlat Next.js 16 UI     │
                          └──────────────┬──────────────┘
                                         │ REST API
                          ┌──────────────▼──────────────┐
                          │   FastAPI Backend Service   │
                          └──────┬───────────────┬──────┘
                                 │               │
                     ┌───────────▼─────┐   ┌─────▼───────────┐
                     │ PostgreSQL (DB) │   │  Redis (Broker) │
                     └─────────────────┘   └─────┬───────────┘
                                                 │
                                 ┌───────────────▼──────────────┐
                                 │    Celery Distributed Engine  │
                                 └───────────────┬──────────────┘
                                                 │
        ┌─────────────┬─────────────┬────────────┼────────────┬─────────────┐
        │             │             │            │            │             │
   ┌────▼────┐   ┌────▼────┐   ┌────▼────┐  ┌────▼────┐  ┌────▼────┐   ┌────▼────┐
   │ Nuclei  │   │Subfinder│   │  HTTPx  │  │ Semgrep │  │  Trivy  │   │Gitleaks │
   │ (DAST)  │   │ (Recon) │   │ (Probe) │  │ (SAST)  │  │  (SCA)  │   │(Secrets)│
   └─────────┘   └─────────┘   └─────────┘  └─────────┘  └─────────┘   └─────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) & Docker Compose
- [uv](https://github.com/astral-sh/uv) (for local backend development)
- [Node.js 20+](https://nodejs.org/) & npm (for frontend development)

### 1. Run with Docker Compose (Full Stack)

1. Clone repository:
   ```bash
   git clone https://github.com/ArjinAlbay/secplat.git
   cd secplat
   ```

2. Setup environment variables:
   ```bash
   cp .env.example .env
   ```

3. Launch services:
   ```bash
   make up
   ```

4. Access applications:
   - **Web UI**: [http://localhost:3000](http://localhost:3000)
   - **API Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

### 2. Local Development

Run the full local environment (Postgres & Redis in Docker, hot-reloading FastAPI backend, Celery worker/beat, and Next.js frontend):

```bash
# Setup backend dependencies
cd backend && uv sync && cd ..

# Setup frontend dependencies
cd frontend && npm install && cd ..

# Start all services concurrently
./dev.sh
```

---

## 🛠️ Testing & Quality Assurance

```bash
# Run backend tests
make test
# Or: cd backend && uv run pytest

# Check code formatting & layer linting
make lint
# Or: cd backend && uv run ruff check src tests && uv run lint-imports

# Format code
make fmt
```

---

## 🗺️ Roadmap & Future Scope

- [ ] **CI/CD Integration & Quality Gates**: PR comments with diff scanners and build breaker triggers.
- [ ] **SecPlat CLI**: Terminal utility to initiate audits and enforce local policies.
- [ ] **Issue Tracker Sync**: Bi-directional synchronization with Jira, GitHub Issues, and GitLab.
- [ ] **Alerting & Webhooks**: Slack, Microsoft Teams, and Discord security alerts.
- [ ] **Enterprise Multi-Tenancy & RBAC**: Granular role-based access control and SAML/OIDC SSO support.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
