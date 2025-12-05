# MALIEV Microservices Constitution

<!--
SYNC IMPACT REPORT
==================
Version Change: 1.6.0 → 1.7.0 (Amendment: Code Quality Standards & Scalar Adoption)
Ratification Date: 2025-12-04
Last Amendment: 2025-12-04

UPDATES:
- Added Principle XIV: Code Quality & Library Standards (NON-NEGOTIABLE)
  - BANNED: AutoMapper, FluentValidation, FluentAssertions
- Updated Principle II: Replaced Swagger with Scalar for API documentation

TEMPLATE UPDATES REQUIRED:
✅ constitution.md — Added Principle XIV, Updated Principle II
🔄 All microservices — Remove banned libraries, migrate to Scalar
🔄 All specs — plan.md must validate compliance

FOLLOW-UP ITEMS:
- Audit all services for banned libraries
- Schedule migration tasks for non-compliant services
-->

<!--
PREVIOUS SYNC IMPACT REPORT
===========================
Version Change: 1.5.0 → 1.6.0 (Amendment: .NET Aspire Integration & GitHub Packages)
Ratification Date: 2025-10-02
Last Amendment: 2025-11-21

UPDATES:
- Added Principle XIII: .NET Aspire Integration (NON-NEGOTIABLE)
- ServiceDefaults must be consumed as NuGet package from GitHub Packages
- Docker builds must use BuildKit secrets for NuGet authentication
- CI/CD must authenticate with GITOPS_PAT (not GITHUB_TOKEN) for cross-repo packages

TEMPLATE UPDATES REQUIRED:
✅ constitution.md — Added Principle XIII for Aspire integration
🔄 All microservices — Must update to use PackageReference for ServiceDefaults
🔄 All Dockerfiles — Must use BuildKit secrets syntax
🔄 All CI workflows — Must pass NuGet credentials

FOLLOW-UP ITEMS:
- Update remaining 19 microservices to use GitHub Packages for ServiceDefaults
- Verify all GITOPS_PAT secrets have read:packages scope
- Update CI workflows to use BuildKit secret flags in docker build
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

* All APIs documented via **OpenAPI/Scalar**
* Data contracts versioned (MAJOR.MINOR)
* Backward-compatible migrations mandatory

**Rationale:** Prevents breaking changes and preserves consumer stability. Scalar provides a more modern and performant API documentation experience.

---

### III. Test-First Development (NON-NEGOTIABLE)

* Tests authored **immediately after specification approval**, before implementation
* Code must **fail tests first** (Red–Green–Refactor)
* Unit, integration, and contract tests mandatory
* Minimum 80 % coverage for business-critical logic
* Test code reviewed equally with production code

**Rationale:** Ensures correctness before coding and keeps system behavior verifiable.

---

### IV. Real Infrastructure Testing (NON-NEGOTIABLE)

* **ALL tests MUST use real infrastructure dependencies** via Testcontainers - no in-memory substitutes allowed
* **PostgreSQL**: Real PostgreSQL instances required (no EF Core InMemoryDatabase provider permitted)
* **RabbitMQ**: Real RabbitMQ instances required for message queue testing (no in-memory message buses)
* **Redis**: Real Redis instances required for caching and distributed locking tests (no in-memory cache providers)
* Integration tests MUST use Docker containers for all infrastructure (local/CI)
* Test isolation achieved through database transactions, queue purging, or cleanup scripts
* Test infrastructure must mirror production configuration exactly (same versions, same settings)

**Rationale:** In-memory substitutes have different behavior, concurrency handling, and constraints than real infrastructure. Testing against production-like infrastructure catches real-world issues early (distributed locking race conditions, message serialization, connection pooling, transaction isolation) and eliminates false positives from in-memory quirks. This ensures test fidelity and production confidence across all infrastructure layers.

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
* Multi-stage builds mandatory: SDK for build, ASP.NET runtime for final image
* Use .NET 10 base images: `mcr.microsoft.com/dotnet/sdk:10.0` and `mcr.microsoft.com/dotnet/aspnet:10.0`
* Set ownership with `chown -R app:app /app` **BEFORE** the `USER app` directive, then COPY files as `app` user
* Use `.dockerignore` to exclude build outputs, IDE files, specs, CI/CD files, **and Test projects**
* BuildKit secrets mandatory for NuGet credentials: `--mount=type=secret,id=nuget_username`
* Health checks must validate service liveness endpoint: `HEALTHCHECK CMD curl -f http://localhost:8080/[service-name]/liveness || exit 1`
* Optimize layer caching by copying project files before source code
* Expose port 8080: `EXPOSE 8080` and `ENV ASPNETCORE_URLS=http://+:8080`

**Standard Dockerfile Pattern:**

```dockerfile
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY nuget.config ./
COPY ["Service.Api/Service.Api.csproj", "Service.Api/"]
RUN --mount=type=secret,id=nuget_username \
    --mount=type=secret,id=nuget_password \
    NUGET_USERNAME=$(cat /run/secrets/nuget_username) \
    NUGET_PASSWORD=$(cat /run/secrets/nuget_password) \
    dotnet restore "Service.Api/Service.Api.csproj"
COPY . .
WORKDIR "/src/Service.Api"
RUN dotnet publish -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
RUN chown -R app:app /app
USER app
COPY --from=build /app/publish .
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
HEALTHCHECK CMD curl -f http://localhost:8080/[service-name]/liveness || exit 1
ENTRYPOINT ["dotnet", "Service.Api.dll"]
```

**Rationale:** Microsoft's built-in `app` user provides security without complexity. BuildKit secrets prevent credential exposure in Docker image layers. Following Docker best practices ensures consistent, secure, and efficient container images across all services.

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

### XIII. .NET Aspire Integration (NON-NEGOTIABLE)

* **ServiceDefaults as NuGet Package**: All microservices MUST consume `Maliev.Aspire.ServiceDefaults` as a NuGet package from GitHub Packages, NOT as a project reference
* **Package Source Configuration**: Each repository MUST have a `nuget.config` file pointing to GitHub Packages with credential placeholders
* **CI/CD Authentication**: Workflows MUST use `GITOPS_PAT` (with `read:packages` scope) for NuGet authentication - `GITHUB_TOKEN` is insufficient for cross-repo packages
* **Docker BuildKit Secrets**: Dockerfiles MUST use BuildKit secrets (`--mount=type=secret`) for NuGet credentials - using `ARG` for credentials is FORBIDDEN (exposes in image layers)
* **Program.cs Integration**: All services MUST call `builder.AddServiceDefaults()` and `app.MapDefaultEndpoints()`
* **nuget.config Mandatory**: Repository root MUST contain `nuget.config` with GitHub Packages source and `%NUGET_USERNAME%`/`%NUGET_PASSWORD%` placeholders

**Rationale:** Each microservice has its own Git repository. Project references (`../../Maliev.Aspire/...`) fail in CI because the Aspire repository is not present in the microservice's checkout context. Using a NuGet package from GitHub Packages enables independent CI/CD pipelines while maintaining shared observability standards. BuildKit secrets prevent credential exposure in Docker image layers.

---

### XIV. Code Quality & Library Standards (NON-NEGOTIABLE)

* **NO AutoMapper**: Explicit mapping only.
  * **Rationale**: AutoMapper hides references, makes refactoring difficult, and introduces runtime errors that should be compile-time errors. Explicit mapping is explicit, searchable, and performant.
* **NO FluentValidation**: Use standard .NET DataAnnotations or manual validation logic.
  * **Rationale**: FluentValidation adds unnecessary complexity and abstraction. Standard validation is built-in, sufficient, and reduces dependency bloat.
* **NO FluentAssertions**: Use standard xUnit `Assert`.
  * **Rationale**: FluentAssertions adds a large dependency and encourages readable but sometimes ambiguous assertions. Standard `Assert` is part of the test framework, faster, and sufficient.

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

**Version:** 1.7.0 | **Ratified:** 2025-12-04 | **Last Amended:** 2025-12-04
