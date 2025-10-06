# Implementation Plan: JWT Token-Based Authentication Service

**Branch**: `001-create-a-jwt` | **Date**: 2025-10-05 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `specs/001-create-a-jwt/spec.md`

## Execution Flow (/plan command scope)
```
1. Load feature spec from Input path ✅
   → Spec loaded successfully with 73 functional requirements
2. Fill Technical Context ✅
   → All technical decisions specified, no NEEDS CLARIFICATION remain
   → Project Type: Single microservice (ASP.NET Core Web API)
   → Structure Decision: Clean Architecture with Api/Data/Tests projects
3. Fill the Constitution Check section ✅
   → No project-specific constitution found
   → Using CLAUDE.md standard microservice patterns as guidance
4. Evaluate Constitution Check section ✅
   → PASS - No constitutional violations detected
5. Execute Phase 0 → research.md ✅
   → Created research.md with 8 technical research topics
   → All technology decisions documented (ES256, token rotation, Redis pub/sub, etc.)
6. Execute Phase 1 → contracts, data-model.md, quickstart.md, CLAUDE.md update ✅
   → Created data-model.md (3 entities with relationships)
   → Created contracts/openapi.yaml (complete API specification)
   → Created quickstart.md (8 manual testing scenarios)
   → Updated CLAUDE.md with new technology context
7. Re-evaluate Constitution Check section ✅
   → PASS - All patterns align with CLAUDE.md standards
8. Plan Phase 2 → Describe task generation approach ✅
   → Task generation strategy documented in plan.md
   → Estimated 45-50 tasks in dependency order
9. STOP - Ready for /tasks command ✅
   → Planning phase complete
   → All artifacts generated successfully
```

**IMPORTANT**: The /plan command STOPS at step 9. Phases 2-4 are executed by other commands:
- Phase 2: /tasks command creates tasks.md
- Phase 3-4: Implementation execution (manual or via tools)

## Summary

Implement a production-ready JWT token-based authentication service as a .NET 9 microservice that:
- Generates and validates JWT access tokens (15 min expiry) and refresh tokens (7 days expiry)
- Implements OAuth 2.0 RFC 9700 compliant refresh token rotation with automatic reuse detection
- Supports multi-user type authentication (customer and employee) via configurable external validation endpoints
- Provides comprehensive security features including SHA-256 token hashing, dual-factor rate limiting, progressive delays, circuit breaker pattern, and distributed token revocation
- Exposes token validation endpoints returning full user identity (user_id, user_type, username, email, roles, permissions)
- Delivers comprehensive observability with OpenTelemetry distributed tracing, structured logging, and Prometheus metrics

**Technical Approach**: Clean Architecture ASP.NET Core 9.0 microservice with Entity Framework Core 9.0.9 + PostgreSQL 18 for refresh token persistence, Polly for resilience patterns, built-in ASP.NET Core rate limiting, and EdDSA/ES256 asymmetric JWT signing.

## Technical Context

**Language/Version**: C# 13 / .NET 9.0
**Primary Dependencies**:
- ASP.NET Core 9.0 (Web API, Authentication.JwtBearer 9.0.8)
- Entity Framework Core 9.0.9 with Npgsql 9.0.2
- Serilog 8.0.2 (structured logging)
- Polly 8.x (circuit breaker, retry policies)
- System.Security.Cryptography (EdDSA/ES256 signing, SHA-256 hashing)
- AutoMapper 12.0.1, FluentValidation 11.5.1
- Microsoft.OpenApi 9.0.0

**Storage**: PostgreSQL 18 (refresh tokens with SHA-256 hashes, token families, revocation tracking)
**Testing**:
- xUnit 2.9.0 (unit/integration tests)
- FluentAssertions 8.6.0
- Moq 4.20.72
- Testcontainers for PostgreSQL integration tests

**Target Platform**: Linux containers (Docker) on Google Kubernetes Engine (GKE)
**Project Type**: Single microservice with 3 projects (Api, Data, Tests)

**Performance Goals**:
- Authentication: <200ms p95 (including external validation)
- Token validation: <50ms p95 (local validation only)
- Token refresh: <100ms p95 (DB read + write)
- Throughput: 1000 req/s per pod

**Constraints**:
- Stateless microservice (horizontal scaling)
- <2 second token revocation propagation across distributed system
- 30-60 second clock skew tolerance
- Circuit breaker: 5 failures → 30s open
- External service timeout: 5s max

**Scale/Scope**:
- 10,000+ concurrent users
- 100,000+ refresh tokens in database
- Multi-environment (dev/staging/prod) with separate signing keys
- Service-to-service authentication for 20+ microservices

## Constitution Check
*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

**Standard Microservice Patterns (from CLAUDE.md):**

- ✅ **Clean Architecture**: Controllers → Services → Data (3-layer separation)
  - No violation: Standard pattern for authentication service

- ✅ **Stateless Microservice**: All state in PostgreSQL, no in-memory sessions
  - No violation: Enables horizontal scaling

- ✅ **Simple MemoryCache Configuration**: `builder.Services.AddMemoryCache()` without SizeLimit
  - No violation: Rate limiting and validation cache

- ✅ **Health Checks**: Liveness + Readiness endpoints
  - No violation: `/auth/liveness`, `/auth/readiness` with PostgreSQL check

- ✅ **Serilog Console-Only Logging**: Structured logging to stdout
  - No violation: Standard observability pattern

- ✅ **JWT Authentication**: ASP.NET Core JWT Bearer
  - No violation: Core feature requirement

- ✅ **No Secrets in Code**: Google Secret Manager via `/mnt/secrets`
  - No violation: All keys and URLs from mounted secrets

- ✅ **Zero Build Warnings**: Treat warnings as errors
  - No violation: CI/CD enforcement

- ✅ **GitOps Deployment**: Kustomize with ArgoCD
  - No violation: Standard deployment pattern

- ✅ **Standard Package Versions**: EF Core 9.0.9, Npgsql 9.0.2, Serilog 8.0.2, Microsoft.OpenApi 9.0.0
  - No violation: All versions align with CLAUDE.md

**Additional Pattern Compliance:**

- ✅ **Middleware Order**: Swagger → HTTPS → RateLimit → Authentication → Authorization
  - No violation: Exact order from CLAUDE.md template

- ✅ **Database Migration**: EF Core migrations with port-forward to pod (not service)
  - No violation: Standard migration process

- ✅ **Testing Environment**: PostgreSQL Testcontainers for integration tests
  - No violation: Clean test isolation

**Result**: ✅ **PASS** - No constitutional violations detected

## Project Structure

### Documentation (this feature)
```
specs/001-create-a-jwt/
├── plan.md              # This file (/plan command output)
├── research.md          # Phase 0 output - Technology decisions and patterns
├── data-model.md        # Phase 1 output - Entity design and relationships
├── quickstart.md        # Phase 1 output - Manual testing guide
├── contracts/           # Phase 1 output - OpenAPI specs and contract tests
│   ├── openapi.yaml     # Complete API specification
│   ├── auth.contract.json      # Authentication endpoint contracts
│   ├── refresh.contract.json   # Token refresh contracts
│   └── validate.contract.json  # Token validation contracts
└── tasks.md             # Phase 2 output (/tasks command - NOT created by /plan)
```

### Source Code (repository root)
```
Maliev.AuthService/
├── Maliev.AuthService.Api/
│   ├── Controllers/
│   │   └── AuthenticationController.cs      # POST /auth/login, /auth/refresh, /auth/validate, /auth/revoke
│   ├── Services/
│   │   ├── IAuthenticationService.cs        # Core authentication orchestration
│   │   ├── AuthenticationService.cs
│   │   ├── ITokenGenerator.cs               # JWT generation (access + refresh)
│   │   ├── TokenGenerator.cs
│   │   ├── ITokenValidator.cs               # JWT validation logic
│   │   ├── TokenValidator.cs
│   │   ├── IRefreshTokenService.cs          # Refresh token CRUD + rotation
│   │   ├── RefreshTokenService.cs
│   │   ├── IExternalValidationService.cs    # Customer/Employee validation
│   │   ├── ExternalValidationService.cs
│   │   ├── IRateLimitService.cs             # Dual-factor rate limiting
│   │   ├── RateLimitService.cs
│   │   ├── ITokenRevocationService.cs       # Distributed revocation events
│   │   └── TokenRevocationService.cs
│   ├── Middleware/
│   │   ├── CorrelationIdMiddleware.cs       # X-Correlation-ID propagation
│   │   └── ExceptionHandlingMiddleware.cs   # Global error handling
│   ├── Models/
│   │   ├── LoginRequest.cs                  # {username, password, user_type}
│   │   ├── LoginResponse.cs                 # {access_token, refresh_token, expires_in}
│   │   ├── RefreshRequest.cs                # {refresh_token}
│   │   ├── ValidateResponse.cs              # {user_id, user_type, username, email, roles, permissions}
│   │   ├── RevokeRequest.cs                 # {access_token, reason}
│   │   └── UserType.cs                      # enum {Customer, Employee}
│   ├── Options/
│   │   ├── JwtOptions.cs                    # Issuer, Audience, SigningKey, AccessTokenExpiry, RefreshTokenExpiry
│   │   ├── ExternalServiceOptions.cs        # CustomerValidationUrl, EmployeeValidationUrl, Timeout, RetryPolicy
│   │   ├── RateLimitOptions.cs              # AccountLimit, IpLimit, ProgressiveDelays
│   │   └── CircuitBreakerOptions.cs         # FailureThreshold, OpenDuration
│   ├── HealthChecks/
│   │   ├── PostgresHealthCheck.cs
│   │   └── ExternalServiceHealthCheck.cs
│   ├── Program.cs                           # Service configuration and middleware pipeline
│   ├── appsettings.json                     # Non-sensitive config only
│   ├── appsettings.Development.json         # Local development overrides
│   └── Maliev.AuthService.Api.csproj
│
├── Maliev.AuthService.Data/
│   ├── DbContexts/
│   │   └── AuthDbContext.cs                 # EF Core context for refresh tokens
│   ├── Entities/
│   │   ├── RefreshToken.cs                  # {Id, TokenHash, UserId, UserType, FamilyId, CreatedAt, ExpiresAt, IsRevoked, IsUsed}
│   │   ├── TokenFamily.cs                   # {FamilyId, UserId, UserType, CreatedAt, LastUsedAt}
│   │   └── RevokedAccessToken.cs            # {Jti, RevokedAt, ExpiresAt, Reason}
│   ├── Repositories/
│   │   ├── IRefreshTokenRepository.cs
│   │   ├── RefreshTokenRepository.cs
│   │   ├── ITokenFamilyRepository.cs
│   │   └── TokenFamilyRepository.cs
│   ├── Migrations/
│   │   └── [EF Core migration files]
│   ├── DesignTimeDbContextFactory.cs        # Design-time migrations
│   └── Maliev.AuthService.Data.csproj
│
├── Maliev.AuthService.Tests/
│   ├── Contract/
│   │   ├── AuthenticationContractTests.cs   # POST /auth/login contract validation
│   │   ├── RefreshContractTests.cs          # POST /auth/refresh contract validation
│   │   └── ValidateContractTests.cs         # POST /auth/validate contract validation
│   ├── Integration/
│   │   ├── AuthenticationFlowTests.cs       # End-to-end login → validate → refresh flows
│   │   ├── TokenRotationTests.cs            # Token rotation and reuse detection
│   │   ├── RateLimitingTests.cs             # Account + IP rate limiting
│   │   ├── CircuitBreakerTests.cs           # External service failure scenarios
│   │   └── TokenRevocationTests.cs          # Distributed revocation propagation
│   ├── Unit/
│   │   ├── TokenGeneratorTests.cs           # JWT generation logic
│   │   ├── TokenValidatorTests.cs           # JWT validation logic
│   │   ├── RefreshTokenServiceTests.cs      # Token rotation, reuse detection
│   │   ├── ExternalValidationServiceTests.cs
│   │   └── RateLimitServiceTests.cs
│   ├── Fixtures/
│   │   ├── TestDatabaseFixture.cs           # PostgreSQL Testcontainer setup
│   │   └── TestDataFactory.cs               # Test data builders
│   └── Maliev.AuthService.Tests.csproj
│
├── .github/
│   └── workflows/
│       ├── ci-develop.yml                   # Build → Test → Docker → GitOps update
│       ├── ci-staging.yml
│       └── ci-main.yml
│
├── Dockerfile                               # Multi-stage build (restore → build → publish → runtime)
├── .dockerignore
├── Maliev.AuthService.sln
└── README.md
```

**Structure Decision**: Single microservice architecture with Clean Architecture layering:
- **Api Layer**: Controllers, Services, Middleware (business logic and HTTP handling)
- **Data Layer**: EF Core entities, repositories, migrations (data access and persistence)
- **Tests Layer**: Contract, Integration, Unit tests (comprehensive test coverage)

This structure follows the mandatory Maliev service template from CLAUDE.md with 3-layer separation and stateless microservice design.

## Phase 0: Outline & Research

**Status**: No NEEDS CLARIFICATION in Technical Context - All technology decisions are specified

Since all technical decisions are provided in the /plan command arguments, Phase 0 research will focus on **architectural patterns and security implementation details** rather than technology choices.

### Research Tasks

1. **JWT Signing Algorithm Implementation**
   - Decision: EdDSA (Ed25519) or ES256 (ECDSA P-256)
   - Research: .NET 9 System.Security.Cryptography support for asymmetric algorithms
   - Rationale: RFC 7518 recommends EdDSA for modern systems, ES256 for broad compatibility
   - Output: Key generation, signing, and verification patterns for .NET 9

2. **Refresh Token Rotation & Reuse Detection**
   - Decision: Token family tracking with database persistence
   - Research: OAuth 2.0 RFC 9700 implementation patterns
   - Rationale: Detect stolen tokens by invalidating entire family on reuse
   - Output: Database schema, service logic, and transaction handling

3. **Distributed Token Revocation**
   - Decision: Event-based revocation with <2s propagation
   - Research: Implementation options (Redis Pub/Sub, RabbitMQ, Kafka, HTTP push)
   - Rationale: Need fast propagation across 20+ microservices
   - Output: Selected event system and integration pattern

4. **SHA-256 Token Hashing**
   - Decision: Cryptographic hashing with constant-time comparison
   - Research: .NET 9 SHA-256 implementation and timing attack prevention
   - Rationale: RFC 6819 requires one-way hashing for stored tokens
   - Output: Hashing and comparison code patterns

5. **Dual-Factor Rate Limiting**
   - Decision: ASP.NET Core built-in rate limiting middleware
   - Research: .NET 9 rate limiting with multiple policies (account + IP)
   - Rationale: Prevent credential stuffing with IP-based limits
   - Output: Configuration and custom policy implementation

6. **Circuit Breaker for External Services**
   - Decision: Polly 8.x with typed HTTP clients
   - Research: Circuit breaker configuration for customer/employee validation
   - Rationale: Fail fast when external services are down
   - Output: Polly policy configuration and health check integration

7. **OpenTelemetry Distributed Tracing**
   - Decision: OpenTelemetry .NET SDK with correlation ID propagation
   - Research: Integration with ASP.NET Core 9.0 and Prometheus
   - Rationale: FR-042 requires correlation ID propagation and trace context
   - Output: Instrumentation configuration and custom activity sources

8. **Database Optimistic Concurrency**
   - Decision: RowVersion column on RefreshToken entity
   - Research: EF Core 9.0.9 concurrency token patterns
   - Rationale: Prevent race conditions during token rotation
   - Output: Entity configuration and retry logic

### Research Output Structure (`research.md`)

```markdown
# Technical Research: JWT Authentication Service

## 1. JWT Signing Algorithm (EdDSA vs ES256)
- **Decision**: EdDSA (Ed25519) primary, ES256 fallback
- **Rationale**: [Details from research]
- **Alternatives Considered**: [ES256, RS256, HS256]
- **Implementation**: [Code patterns]

## 2. Refresh Token Rotation Architecture
- **Decision**: [Selected pattern]
- **Rationale**: [OAuth 2.0 RFC 9700 compliance]
- **Database Schema**: [Entity design]
- **Reuse Detection Logic**: [Service implementation]

## 3. Distributed Token Revocation
- **Decision**: [Redis Pub/Sub / RabbitMQ / Kafka / HTTP]
- **Rationale**: [Performance, latency, complexity trade-offs]
- **Integration Pattern**: [.NET implementation]
- **Fallback Strategy**: [When events delayed]

[... continued for all 8 research tasks]
```

**Phase 0 Output**: `research.md` with detailed technical decisions and implementation patterns

## Phase 1: Design & Contracts

*Prerequisites: research.md complete*

### 1. Data Model Design (`data-model.md`)

Extract entities from feature spec and map to EF Core design:

**Entities**:
- `RefreshToken`: TokenHash (string, indexed), UserId (Guid), UserType (enum), FamilyId (Guid, indexed), CreatedAt (DateTimeOffset), ExpiresAt (DateTimeOffset), IsRevoked (bool), IsUsed (bool), RevokedAt (nullable), RowVersion (timestamp)
- `TokenFamily`: FamilyId (Guid, PK), UserId (Guid, indexed), UserType (enum), CreatedAt (DateTimeOffset), LastUsedAt (DateTimeOffset)
- `RevokedAccessToken`: Jti (string, PK), RevokedAt (DateTimeOffset), ExpiresAt (DateTimeOffset), Reason (string)

**Relationships**:
- RefreshToken → TokenFamily (many-to-one via FamilyId)

**Validation Rules**:
- TokenHash: Required, SHA-256 (64 hex chars)
- FamilyId: Required, must exist in TokenFamily
- ExpiresAt: Must be > CreatedAt
- IsUsed + IsRevoked: Mutually tracked for reuse detection

**State Transitions**:
- Active (IsUsed=false, IsRevoked=false) → Used (IsUsed=true on rotation)
- Active/Used → Revoked (IsRevoked=true on family invalidation)

**Indexes**:
- RefreshToken: Composite index on (UserId, UserType, IsRevoked, IsUsed)
- RefreshToken: Index on FamilyId for family invalidation queries
- RefreshToken: Index on TokenHash for lookup
- TokenFamily: Index on UserId for user logout scenarios

### 2. API Contracts (`contracts/openapi.yaml`)

Generate OpenAPI 3.1 specification from functional requirements:

**Endpoints**:

```yaml
POST /auth/login
  Request: {username, password, user_type: "customer"|"employee"}
  Response 200: {access_token, refresh_token, token_type: "Bearer", expires_in: 900}
  Response 401: {error: "invalid_credentials", error_description}
  Response 429: {error: "too_many_requests", retry_after: 900}
  Response 503: {error: "service_unavailable"} # Circuit breaker open

POST /auth/refresh
  Request: {refresh_token}
  Response 200: {access_token, refresh_token, token_type: "Bearer", expires_in: 900}
  Response 401: {error: "invalid_token"|"token_revoked"|"token_family_invalidated"}
  Response 429: {error: "too_many_requests"}

POST /auth/validate
  Request: {access_token}
  Response 200: {user_id, user_type, username, email, roles: [], permissions: []}
  Response 401: {error: "invalid_token"|"token_expired"|"token_revoked"}

POST /auth/revoke
  Request: {access_token, reason: "user_logout"|"password_changed"|"admin_action"}
  Response 204: No Content
  Response 401: {error: "invalid_token"}

GET /auth/liveness
  Response 200: "Healthy"

GET /auth/readiness
  Response 200: {status: "Healthy", checks: [{name: "PostgreSQL", status: "Healthy"}]}
  Response 503: {status: "Unhealthy", checks: [...]}
```

**Security Schemes**:
```yaml
securitySchemes:
  BearerAuth:
    type: http
    scheme: bearer
    bearerFormat: JWT
```

**Contract Tests** (generated from OpenAPI):
- `AuthenticationContractTests.cs`: Validate request/response schemas for /auth/login
- `RefreshContractTests.cs`: Validate token rotation response structure
- `ValidateContractTests.cs`: Validate user identity response structure

All contract tests **MUST FAIL** initially (no implementation yet).

### 3. Integration Test Scenarios (`quickstart.md`)

Extract from user stories and map to manual/automated test steps:

**Scenario 1: Customer Login Flow**
```bash
# Step 1: Login as customer
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "customer@example.com", "password": "test123", "user_type": "customer"}'

# Expected: 200 OK with access_token + refresh_token

# Step 2: Validate access token
curl -X POST http://localhost:8080/auth/validate \
  -H "Content-Type: application/json" \
  -d '{"access_token": "<ACCESS_TOKEN>"}'

# Expected: 200 OK with user_id, user_type: "customer", email, roles

# Step 3: Refresh token
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<REFRESH_TOKEN>"}'

# Expected: 200 OK with NEW access_token + NEW refresh_token
```

**Scenario 2: Token Reuse Detection**
```bash
# Step 1: Login
# Step 2: Refresh token (save old refresh_token)
# Step 3: Try to reuse OLD refresh_token

# Expected: 401 Unauthorized with error: "token_family_invalidated"
# Verify: ALL tokens in family are revoked
```

**Scenario 3: Rate Limiting**
```bash
# Step 1: Make 5 failed login attempts with wrong password
# Expected: 5th attempt returns 429 Too Many Requests
# Step 2: Wait 15 minutes, retry
# Expected: Account unlocked, login succeeds
```

[Additional scenarios for employee login, circuit breaker, revocation, service auth...]

### 4. Update CLAUDE.md

Run the update script to incrementally add new context:

```powershell
.\.specify\scripts\powershell\update-agent-context.ps1 -AgentType claude
```

**Expected Changes**:
- Add recent changes section: "Implemented JWT authentication service with OAuth 2.0 RFC 9700 compliance"
- Add technology context: "EdDSA/ES256 JWT signing, Polly circuit breaker, ASP.NET Core rate limiting"
- Preserve existing manual additions
- Keep total lines < 150

**Phase 1 Outputs**:
- ✅ `data-model.md` (3 entities with relationships and validation)
- ✅ `contracts/openapi.yaml` (Complete API specification)
- ✅ `contracts/*.contract.json` (Contract test data)
- ✅ Contract test files (failing tests in Tests/Contract/)
- ✅ `quickstart.md` (Manual testing guide with curl examples)
- ✅ `CLAUDE.md` updated (O(1) incremental update)

## Phase 2: Task Planning Approach

*This section describes what the /tasks command will do - DO NOT execute during /plan*

**Task Generation Strategy**:

1. **Load task template**: `.specify/templates/tasks-template.md`

2. **Generate from Phase 1 artifacts**:
   - **From data-model.md** → Entity creation tasks
     - Task: Create RefreshToken entity with EF Core configuration [P]
     - Task: Create TokenFamily entity with EF Core configuration [P]
     - Task: Create RevokedAccessToken entity with EF Core configuration [P]
     - Task: Create AuthDbContext with DbSets and indexes
     - Task: Generate initial EF Core migration

   - **From contracts/openapi.yaml** → Contract test tasks (TDD)
     - Task: Create failing contract test for POST /auth/login [P]
     - Task: Create failing contract test for POST /auth/refresh [P]
     - Task: Create failing contract test for POST /auth/validate [P]
     - Task: Create failing contract test for POST /auth/revoke [P]

   - **From quickstart.md user stories** → Integration test tasks (TDD)
     - Task: Create failing integration test for customer login flow
     - Task: Create failing integration test for employee login flow
     - Task: Create failing integration test for token rotation
     - Task: Create failing integration test for token reuse detection
     - Task: Create failing integration test for account rate limiting
     - Task: Create failing integration test for IP rate limiting
     - Task: Create failing integration test for circuit breaker
     - Task: Create failing integration test for token revocation

   - **From research.md** → Service implementation tasks
     - Task: Implement TokenGenerator service (EdDSA signing from research)
     - Task: Implement TokenValidator service (algorithm validation from research)
     - Task: Implement RefreshTokenService (rotation logic from research)
     - Task: Implement ExternalValidationService (Polly circuit breaker from research)
     - Task: Implement RateLimitService (dual-factor rate limiting from research)
     - Task: Implement TokenRevocationService (distributed events from research)
     - Task: Implement AuthenticationService (orchestration layer)

   - **From FR requirements** → Controller and middleware tasks
     - Task: Implement AuthenticationController with all endpoints
     - Task: Implement CorrelationIdMiddleware
     - Task: Implement ExceptionHandlingMiddleware
     - Task: Configure Program.cs with middleware pipeline
     - Task: Implement health checks (PostgreSQL, external services)

3. **Ordering Strategy**:
   - **Phase 1 (Database)**: Entity creation → Migration → Repository interfaces → Repository implementations
   - **Phase 2 (Tests First - TDD)**: Contract tests → Integration tests (all failing)
   - **Phase 3 (Implementation)**: Services (unit tested) → Controller → Middleware → Configuration
   - **Phase 4 (Validation)**: Run all tests → Fix failures → Run quickstart.md manually

4. **Parallelization**:
   - Mark independent tasks with [P]:
     - Entity creation (can be done in parallel)
     - Contract test creation (independent per endpoint)
     - Service interface creation (independent)
   - Sequential dependencies:
     - Migration AFTER entities
     - Implementation AFTER tests written
     - Controller AFTER services implemented

**Estimated Output**: 45-50 numbered, dependency-ordered tasks in tasks.md

**Task Categories**:
- Database setup: ~8 tasks
- Test creation (TDD): ~15 tasks
- Service implementation: ~12 tasks
- Controller/Middleware: ~6 tasks
- Configuration & deployment: ~5 tasks
- Validation & documentation: ~4 tasks

**IMPORTANT**: This phase is executed by the /tasks command, NOT by /plan

## Phase 3+: Future Implementation

*These phases are beyond the scope of the /plan command*

**Phase 3**: Task execution (/tasks command creates tasks.md)
**Phase 4**: Implementation (execute tasks.md following TDD principles)
**Phase 5**: Validation (run tests, execute quickstart.md, deploy to dev environment)

## Complexity Tracking

*No constitutional violations - table not needed*

## Progress Tracking

*This checklist is updated during execution flow*

**Phase Status**:
- [x] Phase 0: Research complete (/plan command) - **COMPLETED**
  - ✅ research.md created with 8 technical research topics
  - ✅ All technology decisions documented with implementation patterns
- [x] Phase 1: Design complete (/plan command) - **COMPLETED**
  - ✅ data-model.md created (3 entities: RefreshToken, TokenFamily, RevokedAccessToken)
  - ✅ contracts/openapi.yaml created (complete API specification)
  - ✅ quickstart.md created (8 manual testing scenarios)
  - ✅ CLAUDE.md updated with new technology context
- [x] Phase 2: Task planning complete (/plan command - describe approach only) - **COMPLETED**
  - ✅ Task generation strategy documented
  - ✅ Estimated 45-50 tasks in dependency order
- [ ] Phase 3: Tasks generated (/tasks command) - **READY TO EXECUTE**
- [ ] Phase 4: Implementation complete
- [ ] Phase 5: Validation passed

**Gate Status**:
- [x] Initial Constitution Check: **PASS** - No violations detected
- [x] Post-Design Constitution Check: **PASS** - All patterns align with CLAUDE.md standards
  - ✅ Clean Architecture maintained (Api/Data/Tests separation)
  - ✅ Stateless microservice design (all state in PostgreSQL)
  - ✅ Standard package versions (EF Core 9.0.9, Npgsql 9.0.2, Serilog 8.0.2)
  - ✅ No secrets in code (Google Secret Manager via /mnt/secrets)
  - ✅ Health checks with liveness/readiness endpoints
  - ✅ OpenTelemetry distributed tracing
  - ✅ Polly circuit breaker for resilience
  - ✅ ASP.NET Core built-in rate limiting
- [x] All NEEDS CLARIFICATION resolved: **PASS** - All technical decisions specified
- [x] Complexity deviations documented: **N/A** - No deviations

---
*Based on CLAUDE.md Maliev Microservice Standards - Standard .NET 9 Clean Architecture Pattern*
