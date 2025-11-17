# MALIEV Microservices Constitution

<!--
SYNC IMPACT REPORT
==================
Version Change: 1.2.0 → 1.3.0 (Amendment: Docker Best Practices Enforcement)
Ratification Date: 2025-10-02
Last Amendment: 2025-11-17

NEW PRINCIPLE ADDED:
- X. Docker Best Practices (NON-NEGOTIABLE)

UPDATES:
- All existing principles renumbered (X→XI, XI→XII)
- Docker configuration standardized across all services
- Mandatory use of built-in 'app' user from Microsoft ASP.NET images
- .dockerignore files required for all services
- .NET 10 base images mandated

TEMPLATE UPDATES REQUIRED:
✅ argument.md — updated with Docker Best Practices section
✅ All Dockerfiles — updated to use built-in app user and .NET 10 images
✅ All services — .dockerignore files created

FOLLOW-UP ITEMS:
- Verify CI/CD builds pass with new Docker configurations
- Monitor image sizes after .dockerignore implementation
- Ensure all services follow ownership optimization pattern
-->

## Core Principles

### I. Service Autonomy (NON-NEGOTIABLE)

Each microservice must be **self-contained**:

* Own database and schema
* Own domain logic
* Interact with others only via APIs or events
* No direct database access to another service

**Rationale:** Enables independent deployment, scaling, and ownership.

---

### II. Explicit Contracts

* All APIs documented via **OpenAPI/Swagger**
* Data contracts versioned (MAJOR.MINOR)
* Backward-compatible migrations mandatory

**Rationale:** Prevents breaking changes and preserves consumer stability.

---

### III. Test-First Development (NON-NEGOTIABLE)

* Tests authored **immediately after specification approval**, before implementation
* Code must **fail tests first** (Red–Green–Refactor)
* Unit, integration, and contract tests mandatory
* Minimum 80 % coverage for business-critical logic
* Test code reviewed equally with production code

**Rationale:** Ensures correctness before coding and keeps system behavior verifiable.

---

### IV. PostgreSQL-Only Testing (NON-NEGOTIABLE)

* **ALL tests MUST use PostgreSQL database** - no in-memory databases allowed
* Integration tests MUST use real PostgreSQL instances (Docker containers for local/CI)
* Test isolation achieved through database transactions or cleanup scripts
* No EF Core InMemoryDatabase provider permitted in any test project
* Test databases must mirror production schema exactly

**Rationale:** In-memory databases have different behavior, concurrency handling, and constraints than PostgreSQL. Testing against production-like databases catches real-world issues early and eliminates false positives from in-memory quirks. This ensures test fidelity and production confidence.

---

### V. Auditability & Observability

* Structured JSON logging with traceable user/action IDs
* Immutable audit logs retained per policy
* Health checks for liveness/readiness

**Rationale:** Enables compliance, diagnostics, and operational insight.

---

### VI. Security & Compliance

* JWT authentication, role-based authorization
* Sensitive data encrypted at rest and in transit
* Compliance with GDPR, Thai tax law, and all relevant regulations

---

### VII. Secrets Management & Configuration Security (NON-NEGOTIABLE)

* No secrets in source code
* Secrets injected from **Google Secret Manager**
* Public repositories sanitized of real endpoints
* Commits scanned for secrets before merge

**Rationale:** Prevents leaks and targeted attacks.

---

### VIII. Zero Warnings Policy (NON-NEGOTIABLE)

* Builds must emit zero warnings
* Warnings treated as build failures

**Rationale:** Eliminates technical debt and instability.

---

### IX. Clean Project Artifacts (NON-NEGOTIABLE)

* Remove unused files, outdated docs, and generated artifacts
* `.gitignore` must exclude temporary files
* `.dockerignore` must exclude build artifacts, specs, and IDE files
* Cleanup enforced pre-release

---

### X. Docker Best Practices (NON-NEGOTIABLE)

* **ALL services MUST use the built-in `app` user** from Microsoft's ASP.NET runtime images
* **NO custom user creation** with `useradd`, `adduser`, or `addgroup` commands
* Set ownership with `chown -R app:app /app` **BEFORE** the `USER app` directive
* This ensures copied files inherit correct ownership from the start
* Use `.dockerignore` to exclude build outputs, IDE files, specs, and CI/CD files
* Multi-stage builds mandatory: SDK for build, ASP.NET runtime for final image
* Use .NET 10 base images: `mcr.microsoft.com/dotnet/sdk:10.0` and `mcr.microsoft.com/dotnet/aspnet:10.0`
* Health checks must validate service liveness endpoint
* Install additional tools (like postgresql-client) ONLY when necessary
* Optimize layer caching by copying project files before source code

**Rationale:** Microsoft's built-in `app` user provides security without complexity. Setting ownership before switching users reduces build time and layer complexity. Following Docker best practices ensures consistent, secure, and efficient container images across all services.

---

### XI. Simplicity & Maintainability

* Apply YAGNI
* Favor readable, stateless design
* Shared libraries must be versioned and documented

---

### XII. Business Metrics & Analytics (NON-NEGOTIABLE)

* Every service must expose **business-relevant metrics and analytics endpoints** for use by the company's telemetry pipeline.
* Metrics must quantify both **system health** and **business outcomes**, including (where applicable):

  * Number of processed jobs, quotes, or transactions
  * Active users, conversion rates, and session durations
  * Production throughput, revenue per feature, or machine utilization
* Metrics must use **structured formats** compatible with Prometheus, OpenTelemetry, or other standard collectors.
* Services must tag metrics with:

  * `service_name`
  * `version`
  * `region`
  * `environment` (dev/staging/prod)
* Each release must define a clear mapping between **business objectives** and the metrics implemented.
* Tests must validate the **presence and format** of required metrics endpoints.
* Metrics must not expose confidential or personally identifiable information.

**Rationale:** Analytics convert operational data into measurable business intelligence. This enables data-driven decisions for product strategy, cost optimization, and growth.

---

## Deployment & Operations Standards

* All services containerized via Docker
* Configurable solely by environment variables
* Rate limiting and recovery mechanisms mandatory
* Services must emit metrics consumable by the central telemetry gateway
* Metrics availability verified during deployment pipeline

---

## Development Workflow

**Mandatory sequence:**

1. Specification
2. **Test Definition (includes metrics tests)**
3. Implementation
4. Validation (tests, coverage, analytics endpoints)
5. Refactor

* Pull requests without analytics instrumentation will be rejected.
* CI/CD must verify both functional tests and metrics schema compliance.

---

## Security Compliance & Audit Requirements

* Pre-commit scans for secrets and sensitive endpoints
* Compromised credentials rotated within 24 hours
* Quarterly audits of metrics exposure to ensure no PII leakage

---

## Governance

* Constitution supersedes developer preference.
* All PRs validated for constitutional and analytics compliance.
* Amendments require leadership approval and documented migration plan.
* Violations block merge or deployment.

---

**Version:** 1.3.0 | **Ratified:** 2025-10-02 | **Last Amended:** 2025-11-17
