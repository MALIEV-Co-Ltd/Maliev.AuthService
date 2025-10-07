# Implementation Plan: JWT Token-Based Authentication Service

**Branch**: `001-create-a-jwt` | **Date**: 2025-10-06 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/001-create-a-jwt/spec.md`

## Execution Flow (/plan command scope)

```
1. Load feature spec from Input path
   → ✅ Feature spec loaded and validated
2. Fill Technical Context (scan for NEEDS CLARIFICATION)
   → ✅ Technical context provided via user input - .NET 9 microservice architecture
   → ✅ Project Type: Single microservice (Maliev.AuthService)
3. Fill Constitution Check section
   → ✅ Constitution loaded and evaluated
4. Evaluate Constitution Check section
   → ✅ No violations - design follows all constitutional principles
   → Update Progress Tracking: Initial Constitution Check PASS
5. Execute Phase 0 → research.md
   → IN PROGRESS - Researching technical decisions
6. Execute Phase 1 → contracts, data-model.md, quickstart.md, CLAUDE.md
7. Re-evaluate Constitution Check section
8. Plan Phase 2 → Describe task generation approach (DO NOT create tasks.md)
9. STOP - Ready for /tasks command
```

**IMPORTANT**: The /plan command STOPS at step 8. Phases 2-4 are executed by other commands:

- Phase 2: /tasks command creates tasks.md
- Phase 3-4: Implementation execution (manual or via tools)

## Summary

This feature implements a production-ready JWT token-based authentication service for Maliev Co. Ltd.'s microservices architecture. The service supports dual user types (customers and employees) with configurable external validation endpoints, implements OAuth 2.0 RFC 9700 compliant refresh token rotation with automatic reuse detection, provides comprehensive token lifecycle management (generation, validation, refresh, revocation), and includes distributed access token revocation with Redis pub/sub event propagation. The service follows clean architecture patterns with Entity Framework Core, PostgreSQL persistence, and comprehensive observability through Serilog structured logging and Prometheus metrics.

## Technical Context

**Language/Version**: .NET 9.0 (ASP.NET Core 9.0)
**Primary Dependencies**:

- Entity Framework Core 9.0.9 (data access)
- Npgsql 9.0.2 (PostgreSQL provider)
- Microsoft.OpenApi 9.0.0 (Swagger/OpenAPI)
- Serilog 8.0.2 (structured logging)
- AutoMapper 12.0.1 (object mapping)
- FluentValidation 11.5.1 (request validation)
- Polly (HTTP retry with exponential backoff)
- Asp.Versioning.Http 8.1.0 (API versioning)
- AspNetCore.HealthChecks.UI.Client 8.0.1 (health checks)
- StackExchange.Redis (token revocation pub/sub)

**Storage**: PostgreSQL 18 (auth_app_db database)

- Refresh tokens table (hashed with SHA-256)
- Revoked access tokens table (JTI tracking)
- Token families table (rotation lineage tracking)

**Testing**: MSTest with FluentAssertions, Moq for mocking

- Actual PostgreSQL database (no in-memory fallback)
- TestWebApplicationFactory for integration tests
- Contract tests for all API endpoints
- Minimum 80% coverage for critical functionality

**Target Platform**: Kubernetes (GKE) with Docker containerization

- Multi-stage Docker build (SDK → runtime)
- Non-root user (appuser UID 1000)
- Health checks (liveness/readiness)
- Google Secret Manager for secrets

**Project Type**: Single microservice (Clean Architecture)

- Maliev.AuthService.Api (WebAPI project)
- Maliev.AuthService.Data (Data layer with EF Core)
- Maliev.AuthService.Tests (Contract, Integration, Unit tests)

**Performance Goals**:

- Token validation: <50ms p95 (cryptographic signature verification)
- Token generation: <200ms p95 (includes external validation service call)
- Token refresh: <100ms p95 (database lookup + rotation)
- Revocation propagation: <2 seconds (Redis pub/sub eventual consistency)
- Support 1000+ concurrent token validations per second

**Constraints**:

- Access token expiry: 15 minutes (security requirement)
- Refresh token expiry: 7 days (user convenience vs security balance)
- RSA-SHA256 (RSA-2048) asymmetric signing (no HS256 shared secrets)
- SHA-256 hashing for refresh token storage (no plaintext)
- External validation timeout: 5 seconds total (100ms/200ms/400ms retry)
- Circuit breaker: 5 failures → 30 second open state
- Rate limiting: Account (5/15min), IP (20/15min), Service (1000/min)

**Scale/Scope**:

- Initial deployment: 100-500 concurrent users
- Growth target: 10,000+ users within 6 months
- Multi-tenant: Separate customer and employee user bases
- Token families: Unlimited per user (track rotation lineage)
- Concurrent sessions: Unlimited per user (no restrictions)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

**Full Constitution**: See `.specify/memory/constitution.md` for complete principle definitions and requirements.

**Summary**: All 9 constitutional principles verified:
- **I. Service Autonomy**: ✅ Own database (auth_app_db), HTTP-only external integration
- **II. Explicit Contracts**: ✅ OpenAPI/Swagger, API versioning, contract tests
- **III. Test-First Development**: ✅ Red-Green-Refactor, 80% coverage, tests before implementation
- **IV. Auditability**: ✅ Serilog structured logging, correlation IDs, Prometheus metrics
- **V. Security**: ✅ RSA-SHA256 JWT signing, SHA-256 hashing, OAuth 2.0 RFC 9700 compliance
- **VI. Secrets Management**: ✅ All secrets via Google Secret Manager environment variables
- **VII. Zero Warnings**: ✅ TreatWarningsAsErrors enabled in all projects
- **VIII. Clean Artifacts**: ✅ Proper .gitignore/.dockerignore, no boilerplate files
- **IX. Simplicity**: ✅ YAGNI, stateless design, Clean Architecture pattern

**Initial Constitution Check**: ✅ PASS - All 9 principles satisfied

## Project Structure

### Documentation (this feature)

```
specs/001-create-a-jwt/
├── plan.md              # This file (/plan command output)
├── research.md          # Phase 0 output (/plan command)
├── data-model.md        # Phase 1 output (/plan command)
├── quickstart.md        # Phase 1 output (/plan command)
├── contracts/           # Phase 1 output (/plan command)
│   ├── authentication.openapi.yaml
│   ├── token-validation.openapi.yaml
│   ├── token-refresh.openapi.yaml
│   └── token-revocation.openapi.yaml
└── tasks.md             # Phase 2 output (/tasks command - NOT created by /plan)
```

### Source Code (repository root)

```
Maliev.AuthService/
├── Maliev.AuthService.sln
├── Dockerfile
├── .dockerignore
├── docker-compose.test.yml
├── README.md
├── .gitignore
├── .github/
│   └── workflows/
│       ├── ci-develop.yml
│       ├── ci-staging.yml
│       └── ci-main.yml
├── Maliev.AuthService.Api/
│   ├── Maliev.AuthService.Api.csproj
│   ├── Program.cs
│   ├── appsettings.json
│   ├── appsettings.Development.json
│   ├── Properties/
│   │   └── launchSettings.json
│   ├── Controllers/
│   │   ├── AuthenticationController.cs
│   │   ├── TokenController.cs
│   │   └── ValidationController.cs
│   ├── DTOs/
│   │   ├── Request/
│   │   │   ├── LoginRequest.cs
│   │   │   ├── RefreshTokenRequest.cs
│   │   │   ├── RevokeTokenRequest.cs
│   │   │   └── ValidateTokenRequest.cs
│   │   └── Response/
│   │       ├── LoginResponse.cs
│   │       ├── TokenResponse.cs
│   │       ├── UserIdentityResponse.cs
│   │       └── ErrorResponse.cs
│   ├── Services/
│   │   ├── IAuthenticationService.cs
│   │   ├── AuthenticationService.cs
│   │   ├── ITokenGenerator.cs
│   │   ├── TokenGenerator.cs
│   │   ├── ITokenValidator.cs
│   │   ├── TokenValidator.cs
│   │   ├── IRefreshTokenService.cs
│   │   ├── RefreshTokenService.cs
│   │   ├── IRevocationService.cs
│   │   ├── RevocationService.cs
│   │   ├── IExternalValidationService.cs
│   │   └── ExternalValidationService.cs
│   ├── Middleware/
│   │   ├── ExceptionHandlingMiddleware.cs
│   │   └── RequestLoggingMiddleware.cs
│   ├── Validators/
│   │   ├── LoginRequestValidator.cs
│   │   ├── RefreshTokenRequestValidator.cs
│   │   └── ValidateTokenRequestValidator.cs
│   ├── Options/
│   │   ├── JwtOptions.cs
│   │   ├── ExternalServiceOptions.cs
│   │   ├── RateLimitOptions.cs
│   │   └── CircuitBreakerOptions.cs
│   └── HealthChecks/
│       └── DatabaseHealthCheck.cs
├── Maliev.AuthService.Data/
│   ├── Maliev.AuthService.Data.csproj
│   ├── DbContexts/
│   │   └── AuthDbContext.cs
│   ├── Entities/
│   │   ├── RefreshToken.cs
│   │   ├── RevokedToken.cs
│   │   ├── TokenFamily.cs
│   │   └── UserType.cs (enum)
│   ├── Configurations/
│   │   ├── RefreshTokenConfiguration.cs
│   │   ├── RevokedTokenConfiguration.cs
│   │   └── TokenFamilyConfiguration.cs
│   ├── Repositories/
│   │   ├── IRefreshTokenRepository.cs
│   │   ├── RefreshTokenRepository.cs
│   │   ├── IRevokedTokenRepository.cs
│   │   ├── RevokedTokenRepository.cs
│   │   ├── ITokenFamilyRepository.cs
│   │   └── TokenFamilyRepository.cs
│   ├── Migrations/
│   │   └── (EF Core migrations - generated)
│   └── DesignTimeDbContextFactory.cs
└── Maliev.AuthService.Tests/
    ├── Maliev.AuthService.Tests.csproj
    ├── Fixtures/
    │   ├── TestDatabaseFixture.cs
    │   └── TestWebApplicationFactory.cs
    ├── Contract/
    │   ├── AuthenticationContractTests.cs
    │   ├── TokenRefreshContractTests.cs
    │   ├── TokenValidationContractTests.cs
    │   └── TokenRevocationContractTests.cs
    ├── Integration/
    │   ├── CustomerLoginIntegrationTests.cs
    │   ├── EmployeeLoginIntegrationTests.cs
    │   ├── TokenRotationIntegrationTests.cs
    │   ├── TokenReuseDetectionIntegrationTests.cs
    │   ├── TokenRevocationIntegrationTests.cs
    │   ├── RateLimitingIntegrationTests.cs
    │   ├── CircuitBreakerIntegrationTests.cs
    │   └── ValidationCacheIntegrationTests.cs
    └── Unit/
        ├── TokenGeneratorTests.cs
        ├── TokenValidatorTests.cs
        ├── RefreshTokenServiceTests.cs
        └── ValidatorTests/
            ├── LoginRequestValidatorTests.cs
            └── RefreshTokenRequestValidatorTests.cs
```

**Structure Decision**: Single microservice architecture following Clean Architecture pattern. The service is organized into three projects:

1. **Maliev.AuthService.Api**: WebAPI layer with controllers, DTOs, services, middleware, and validators
2. **Maliev.AuthService.Data**: Data access layer with EF Core DbContext, entities, configurations, repositories, and migrations
3. **Maliev.AuthService.Tests**: Comprehensive test suite with contract tests (API validation), integration tests (end-to-end scenarios), and unit tests (business logic)

The structure separates concerns while maintaining simplicity appropriate for a focused authentication service.

## Phase 0: Outline & Research

**Status**: IN PROGRESS

### Research Tasks

1. **JWT Signing Algorithm Selection** (EdDSA vs RSA vs ECDSA)

   - **Decision made: RSA-2048 (RSA-SHA256)** per FR-018
   - Rationale: Better .NET 9 native support, proven compatibility, industry standard
   - Library: Microsoft.IdentityModel.Tokens with RsaSecurityKey

2. **Refresh Token Storage Strategy** (SHA-256 hashing)
   
   - Decision needed: Confirm SHA-256 hashing per FR-023
   - Research: Constant-time comparison in .NET, hash collision resistance
   - Implementation: `System.Security.Cryptography.SHA256`

3. **Token Revocation Event System** (Redis pub/sub)
   
   - Decision needed: Redis vs Kafka for <2s propagation (FR-060)
   - Research: Redis Pub/Sub vs Kafka performance for low-latency events
   - Library: StackExchange.Redis vs Confluent.Kafka

4. **External Service Circuit Breaker** (Polly configuration)
   
   - Decision needed: Confirm Polly for circuit breaker (FR-067-069)
   - Research: Polly CircuitBreaker policy configuration, metrics integration
   - Pattern: Advanced circuit breaker with half-open state

5. **Rate Limiting Implementation** (ASP.NET Core 9 built-in)
   
   - Decision needed: Confirm ASP.NET Core 9 built-in rate limiting (FR-053-056)
   - Research: Fixed window vs sliding window, IP extraction from headers
   - Implementation: `Microsoft.AspNetCore.RateLimiting`

6. **Database Migration Strategy** (EF Core)
   
   - Decision needed: Manual vs automated migration application
   - Research: Best practices for Kubernetes deployments, idempotent migrations
   - Pattern: Manual migration via `dotnet ef database update` (per constitution)

7. **Token Family Tracking** (Rotation lineage)
   
   - Decision needed: Database schema for family_id, cascading invalidation
   - Research: Efficient queries for token family traversal
   - Pattern: Indexed foreign key with cleanup jobs

8. **Health Check Integration** (Kubernetes liveness/readiness)
   
   - Decision needed: Database connectivity check strategy
   - Research: Fast vs comprehensive health checks, dependency checks
   - Library: AspNetCore.HealthChecks.UI.Client

9. **Distributed Tracing** (OpenTelemetry)
   
   - Decision needed: Correlation ID vs full OpenTelemetry spans
   - Research: .NET 9 Activity API, trace context propagation
   - Library: OpenTelemetry.Extensions.Hosting (optional for Phase 2)

10. **Password Validation Delegation** (External service contracts)
    
    - Decision needed: Request/response format for customer/employee validation
    - Research: Standard authentication API patterns, error handling
    - Pattern: Typed HttpClient with Polly retry

### Research Output Path

`specs/001-create-a-jwt/research.md`

## Phase 1: Design & Contracts

*Prerequisites: research.md complete*

**Status**: PENDING (blocked on Phase 0)

### Deliverables

1. **Data Model** (`data-model.md`):
   
   - RefreshToken entity (id, token_hash, user_id, user_type, family_id, expiry, created_at, last_used_at)
   - RevokedToken entity (jti, user_id, revoked_at, reason, expiry)
   - TokenFamily entity (family_id, user_id, user_type, created_at, last_refresh_at, invalidated, invalidation_reason)
   - UserType enum (Customer, Employee)
   - Relationships and indexes for performance

2. **API Contracts** (`contracts/`):
   
   - **authentication.openapi.yaml**: POST /api/v1/auth/login (LoginRequest → LoginResponse)
   - **token-refresh.openapi.yaml**: POST /api/v1/auth/refresh (RefreshTokenRequest → TokenResponse)
   - **token-validation.openapi.yaml**: POST /api/v1/auth/validate (ValidateTokenRequest → UserIdentityResponse)
   - **token-revocation.openapi.yaml**: POST /api/v1/auth/revoke (RevokeTokenRequest → NoContent)
   - All contracts include error responses (400, 401, 403, 409, 429, 500, 503)

3. **Contract Tests** (failing tests for TDD):
   
   - AuthenticationContractTests.cs (login endpoint validation)
   - TokenRefreshContractTests.cs (refresh endpoint validation)
   - TokenValidationContractTests.cs (validate endpoint validation)
   - TokenRevocationContractTests.cs (revoke endpoint validation)
   - Each test validates request/response schema against OpenAPI contract

4. **Integration Test Scenarios**:
   
   - CustomerLoginIntegrationTests (FR-001, FR-002, FR-008)
   - EmployeeLoginIntegrationTests (FR-001, FR-003, FR-008)
   - TokenRotationIntegrationTests (FR-015 - new refresh token issued)
   - TokenReuseDetectionIntegrationTests (FR-016 - family invalidation)
   - TokenRevocationIntegrationTests (FR-060 - distributed propagation)
   - RateLimitingIntegrationTests (FR-053, FR-054, FR-056)
   - CircuitBreakerIntegrationTests (FR-067, FR-068, FR-069)

5. **Quickstart Guide** (`quickstart.md`):
   
   - Local PostgreSQL setup with docker-compose.test.yml
   - Environment variable configuration (ConnectionStrings__AuthDbContext)
   - Database migration steps
   - Running the service locally
   - Testing authentication flow with curl/Postman examples
   - Validating token rotation and reuse detection

6. **Agent Context File** (`CLAUDE.md` in repository root):
   
   - Project overview and architecture
   - Key technologies and versions
   - Development commands (build, test, run)
   - Common tasks (migrations, debugging)
   - Recent changes tracking (keep last 3 updates)
   - Generated via `.specify/scripts/powershell/update-agent-context.ps1 -AgentType claude`

### Output

- data-model.md with complete entity definitions
- contracts/*.openapi.yaml for all endpoints
- Failing contract tests in Maliev.AuthService.Tests/Contract/
- Integration test structure in Maliev.AuthService.Tests/Integration/
- quickstart.md with step-by-step local setup
- CLAUDE.md in repository root

## Phase 2: Task Planning Approach

*This section describes what the /tasks command will do - DO NOT execute during /plan*

**Task Generation Strategy**:

1. Load `.specify/templates/tasks-template.md` as base template
2. Generate tasks from Phase 1 design documents:
   - Each OpenAPI contract → contract test task [P]
   - Each entity in data model → entity creation + configuration task [P]
   - Each repository interface → repository implementation task [P]
   - Each service interface → service implementation task
   - Each controller → controller implementation task
   - Each user scenario → integration test task
   - Each validator → validator implementation + unit test task [P]

**Ordering Strategy**:

1. **Foundation Layer** (TDD: Tests first):
   
   - Task 1-4: Contract tests (all [P] - can run in parallel)
   - Task 5-7: Entity models and EF Core configurations [P]
   - Task 8: DbContext setup and DesignTimeDbContextFactory
   - Task 9: Initial migration creation
   - Task 10-12: Repository interfaces and implementations [P]

2. **Service Layer**:
   
   - Task 13-14: Token generator interface and implementation
   - Task 15-16: Token validator interface and implementation
   - Task 17-18: Refresh token service interface and implementation
   - Task 19-20: Revocation service interface and implementation
   - Task 21-22: External validation service interface and implementation
   - Task 23-24: Authentication service interface and implementation

3. **API Layer**:
   
   - Task 25-28: FluentValidation validators with unit tests [P]
   - Task 29-32: Controllers (Authentication, Token, Validation, Revocation)
   - Task 33-34: Exception and request logging middleware [P]
   - Task 35: Program.cs configuration and startup

4. **Integration Testing**:
   
   - Task 36: TestDatabaseFixture and TestWebApplicationFactory setup
   - Task 37-44: Integration test scenarios (8 test suites) [P]

5. **Infrastructure**:
   
   - Task 45: Dockerfile and .dockerignore
   - Task 46-48: GitHub Actions workflows (develop, staging, main) [P]
   - Task 49: README.md and quickstart documentation

6. **Final Validation**:
   
   - Task 50: Run all tests and verify 80%+ coverage
   - Task 51: Build and run service locally, execute quickstart.md
   - Task 52: Clean artifacts and verify zero warnings build

**Estimated Output**: 50-52 numbered, ordered tasks in tasks.md

**Parallelization**: Tasks marked [P] are independent and can execute in parallel (same layer, different files/components)

**IMPORTANT**: This phase is executed by the /tasks command, NOT by /plan

## Phase 3+: Future Implementation

*These phases are beyond the scope of the /plan command*

**Phase 3**: Task execution (/tasks command creates tasks.md)
**Phase 4**: Implementation (execute tasks.md following TDD and constitutional principles)
**Phase 5**: Validation (run tests, execute quickstart.md, performance benchmarks, security audit)

## Complexity Tracking

**No violations** - Constitution Check passed without deviations.

This design maintains simplicity while meeting all security and functional requirements:

- Single microservice (not multiple services)
- Standard libraries (no custom frameworks)
- Direct PostgreSQL access (no repository abstraction needed)
- Built-in rate limiting (no external packages)
- Clean Architecture without over-engineering

## Progress Tracking

**Phase Status**:

- [x] Phase 0: Research complete (/plan command) ✅ research.md created
- [x] Phase 1: Design complete (/plan command) ✅ data-model.md, contracts/auth-api.yaml, quickstart.md created
- [x] Phase 2: Task planning complete (/plan command - describe approach only) ✅ Task generation strategy documented
- [ ] Phase 3: Tasks generated (/tasks command) - NEXT STEP
- [ ] Phase 4: Implementation complete
- [ ] Phase 5: Validation passed

**Gate Status**:

- [x] Initial Constitution Check: PASS (all 9 principles satisfied)
- [x] Post-Design Constitution Check: PASS (design maintains constitutional compliance)
- [x] All NEEDS CLARIFICATION resolved: COMPLETE (all 10 research areas documented)
- [x] Complexity deviations documented: N/A (no violations)

**Current Phase**: COMPLETE - Ready for /tasks command

**Deliverables Summary**:

- ✅ plan.md (this file) - 512 lines
- ✅ research.md - 10 technical decisions with rationale
- ✅ data-model.md - 7 entities with PostgreSQL schema
- ✅ contracts/auth-api.yaml - 8 endpoints (OpenAPI 3.0.3)
- ✅ quickstart.md - 6 end-to-end test scenarios

---

*Based on Constitution v1.0.0 - See `.specify/memory/constitution.md`*
