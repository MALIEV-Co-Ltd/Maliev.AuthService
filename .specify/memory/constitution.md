# MALIEV Microservices Constitution

<!--
SYNC IMPACT REPORT
==================
Version Change: 1.2.0 → 1.3.0 (Amendment: PostgreSQL-Only Testing Enforcement)
Ratification Date: 2025-10-02
Last Amendment: 2025-10-16

NEW PRINCIPLE ADDED:
- IV. PostgreSQL-Only Testing (NON-NEGOTIABLE)

UPDATES:
- All existing principles renumbered (IV→V, V→VI, VI→VII, VII→VIII, VIII→IX, IX→X, X→XI)
- Test-First Development (Principle III): Now explicitly complemented by PostgreSQL-only requirement
- Development Workflow: Integration tests must use PostgreSQL in Docker containers
- CI/CD Pipeline: Must provision PostgreSQL test databases

TEMPLATE UPDATES REQUIRED:
✅ spec-template.md — update "Testing Strategy" section to mandate PostgreSQL
✅ plan-template.md — reference Principle IV compliance check
✅ tasks-template.md — ensure all integration test tasks specify PostgreSQL setup
✅ test-setup-template.md — add PostgreSQL Docker Compose configuration

FOLLOW-UP ITEMS:
- Refactor all existing in-memory database tests to use PostgreSQL
- Document PostgreSQL test database setup for local development and CI
- Update CI/CD pipelines to provision PostgreSQL test containers
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
* Cleanup enforced pre-release

---

### X. Simplicity & Maintainability

* Apply YAGNI
* Favor readable, stateless design
* Shared libraries must be versioned and documented

---

### XI. Business Metrics & Analytics (NON-NEGOTIABLE)

* Every service must expose **business-relevant metrics and analytics endpoints** for use by the company’s telemetry pipeline.
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

**Version:** 1.2.0 | **Ratified:** 2025-10-02 | **Last Amended:** 2025-10-09
