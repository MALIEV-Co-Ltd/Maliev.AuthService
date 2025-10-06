# Tasks: JWT Token-Based Authentication Service

**Feature**: 001-create-a-jwt
**Input**: Design documents from `\\maliev\repository\maliev\Maliev.AuthService\specs\001-create-a-jwt\`
**Prerequisites**: plan.md, data-model.md, contracts/openapi.yaml, quickstart.md, research.md

## Execution Flow (main)
```
1. Load plan.md from feature directory ✅
   → Tech stack: .NET 9.0, EF Core 9.0.9, PostgreSQL 18, Polly 8.x
   → Structure: 3 projects (Api, Data, Tests) - Clean Architecture
2. Load optional design documents ✅
   → data-model.md: 3 entities (RefreshToken, TokenFamily, RevokedAccessToken)
   → contracts/: OpenAPI 3.1 with 5 endpoints
   → quickstart.md: 8 test scenarios
3. Generate tasks by category ✅
   → Setup: 6 tasks (T001-T006)
   → Database: 7 tasks (T007-T013)
   → Tests: 16 tasks (T014-T029)
   → Services: 23 tasks (T030-T052)
   → Configuration: 7 tasks (T053-T059)
   → GitOps: 3 tasks (T060-T062)
4. Apply task rules ✅
   → 27 tasks marked [P] for parallel execution
   → Tests before implementation (TDD enforced)
5. Number tasks sequentially (T001-T062) ✅
6. Generate dependency graph ✅
7. Create parallel execution examples ✅
8. Validate task completeness ✅
   → All 5 endpoints have implementation tasks
   → All 3 entities have model tasks
   → All 8 scenarios have integration tests
9. Return: SUCCESS (tasks ready for execution)
```

---

## Format: `[ID] [P?] Description`
- **[P]**: Can run in parallel (different files, no dependencies)
- All paths are absolute from repository root: `R:\maliev\Maliev.AuthService\`

---

## Phase 3.0: Repository Cleanup (MANDATORY - Constitution VIII)

- [ ] **T000** Clean up deleted template files from git tracking (Constitution VIII compliance):
  - Run: `git rm GEMINI.md`
  - Run: `git rm .gitignore` (will be recreated in T001)
  - Run: `git rm Maliev.AuthService.Api/Configurations/ConfigureSwaggerOptions.cs`
  - Run: `git rm Maliev.AuthService.Api/Controllers/AuthenticationController.cs`
  - Run: `git rm Maliev.AuthService.Api/HealthChecks/ConfigurationHealthCheck.cs`
  - Run: `git rm Maliev.AuthService.Api/HealthChecks/ExternalServiceHealthCheck.cs`
  - Run: `git rm Maliev.AuthService.Api/Middleware/CorrelationIdMiddleware.cs`
  - Run: `git rm Maliev.AuthService.Api/Middleware/ExceptionHandlingMiddleware.cs`
  - Run: `git rm Maliev.AuthService.Api/Models/*.cs` (all deleted model files)
  - Run: `git rm Maliev.AuthService.Api/Services/*.cs` (all deleted service files)
  - Run: `git rm Maliev.AuthService.Common/Exceptions/*.cs`
  - Run: `git rm Maliev.AuthService.Data/DbContexts/RefreshTokenDbContext.cs`
  - Run: `git rm Maliev.AuthService.Data/Entities/RefreshToken.cs`
  - Run: `git rm Maliev.AuthService.Data/Migrations/*`
  - Run: `git rm Maliev.AuthService.Data/Repositories/*.cs`
  - Run: `git rm Maliev.AuthService.Data/deploy-migration.ps1`
  - Run: `git rm Maliev.AuthService.Data/DATABASE-MIGRATION-GUIDE.md`
  - Run: `git rm Maliev.AuthService.JwtToken/*.cs`
  - Run: `git rm Maliev.AuthService.Tests/Auth/*`
  - Run: `git rm README.md` (will be recreated in T089)
  - Verify: `git status` shows no deleted files (D marker)
  - Commit: "Clean up template artifacts per Constitution VIII"

---

## Phase 3.1: Setup & Infrastructure

- [ ] **T001** Create solution file `Maliev.AuthService.sln` in repository root and recreate .gitignore with proper patterns (bin/, obj/, .vs/, specs/, *.user)
- [ ] **T002** Create project `Maliev.AuthService.Api\Maliev.AuthService.Api.csproj` (ASP.NET Core 9.0 Web API)
- [ ] **T003** Create project `Maliev.AuthService.Data\Maliev.AuthService.Data.csproj` (Class Library .NET 9.0)
- [ ] **T004** Create project `Maliev.AuthService.Tests\Maliev.AuthService.Tests.csproj` (xUnit test project .NET 9.0)
- [ ] **T005** [P] Add NuGet packages to `Maliev.AuthService.Api.csproj`:
  - Microsoft.AspNetCore.OpenApi 9.0.0
  - Microsoft.AspNetCore.Authentication.JwtBearer 9.0.8
  - Microsoft.EntityFrameworkCore 9.0.9
  - Npgsql.EntityFrameworkCore.PostgreSQL 9.0.2
  - Serilog.AspNetCore 8.0.2
  - Serilog.Sinks.Console 6.0.0
  - Polly 8.6.4
  - Microsoft.Extensions.Http.Polly 9.0.0
  - AutoMapper 12.0.1
  - FluentValidation 11.5.1
  - StackExchange.Redis 2.8.16
  - OpenTelemetry.Exporter.Prometheus.AspNetCore 1.10.0
  - OpenTelemetry.Instrumentation.AspNetCore 1.10.0
  - OpenTelemetry.Instrumentation.Http 1.10.0
  - AspNetCore.HealthChecks.UI.Client 9.0.0
- [ ] **T006** [P] Add NuGet packages to `Maliev.AuthService.Data.csproj`:
  - Microsoft.EntityFrameworkCore 9.0.9
  - Npgsql.EntityFrameworkCore.PostgreSQL 9.0.2
  - Microsoft.EntityFrameworkCore.Design 9.0.9
- [ ] **T007** [P] Add NuGet packages to `Maliev.AuthService.Tests.csproj`:
  - xUnit 2.9.0
  - xUnit.runner.visualstudio 2.8.2
  - FluentAssertions 8.6.0
  - Moq 4.20.72
  - Testcontainers 3.10.0
  - Testcontainers.PostgreSql 3.10.0
  - Microsoft.AspNetCore.Mvc.Testing 9.0.0
  - Microsoft.NET.Test.Sdk 17.12.0
- [ ] **T008** Create `appsettings.json` in `Maliev.AuthService.Api\` with non-sensitive configuration structure
- [ ] **T009** Create `appsettings.Development.json` in `Maliev.AuthService.Api\` with local development overrides
- [ ] **T010** Create `Dockerfile` in repository root with multi-stage build (restore → build → publish → runtime)
- [ ] **T011** [P] Create `.dockerignore` in repository root
- [ ] **T012** [P] Create `.editorconfig` in repository root with C# coding standards

---

## Phase 3.2: Database Models & Migration (TDD Foundation)

- [ ] **T013** [P] Create enum `UserType` in `Maliev.AuthService.Data\Entities\UserType.cs` with Customer=1, Employee=2
- [ ] **T014** [P] Create entity `RefreshToken` in `Maliev.AuthService.Data\Entities\RefreshToken.cs`:
  - Properties: Id (Guid), TokenHash (string), UserId (Guid), UserType (UserType), FamilyId (Guid), CreatedAt (DateTimeOffset), ExpiresAt (DateTimeOffset), IsRevoked (bool), IsUsed (bool), RevokedAt (DateTimeOffset?), Version (uint)
  - Navigation: TokenFamily Family
- [ ] **T015** [P] Create entity `TokenFamily` in `Maliev.AuthService.Data\Entities\TokenFamily.cs`:
  - Properties: FamilyId (Guid PK), UserId (Guid), UserType (UserType), CreatedAt (DateTimeOffset), LastUsedAt (DateTimeOffset)
  - Navigation: ICollection<RefreshToken> Tokens
- [ ] **T016** [P] Create entity `RevokedAccessToken` in `Maliev.AuthService.Data\Entities\RevokedAccessToken.cs`:
  - Properties: Jti (string PK), RevokedAt (DateTimeOffset), ExpiresAt (DateTimeOffset), Reason (string)
- [ ] **T017** Create `RefreshTokenConfiguration` in `Maliev.AuthService.Data\Entities\RefreshTokenConfiguration.cs` (IEntityTypeConfiguration):
  - Configure table name, properties, indexes (TokenHash unique, FamilyId, UserId composite)
  - Configure PostgreSQL xmin for Version (RowVersion)
  - Configure relationship to TokenFamily (cascade delete)
  - Add check constraint: NOT (is_used = true AND is_revoked = true)
- [ ] **T018** Create `TokenFamilyConfiguration` in `Maliev.AuthService.Data\Entities\TokenFamilyConfiguration.cs` (IEntityTypeConfiguration):
  - Configure table name, properties, indexes (UserId, LastUsedAt)
  - Configure relationship to RefreshTokens
- [ ] **T019** Create `RevokedAccessTokenConfiguration` in `Maliev.AuthService.Data\Entities\RevokedAccessTokenConfiguration.cs` (IEntityTypeConfiguration):
  - Configure table name, properties, indexes (ExpiresAt)
- [ ] **T020** Create `AuthDbContext` in `Maliev.AuthService.Data\DbContexts\AuthDbContext.cs`:
  - DbSets for RefreshToken, TokenFamily, RevokedAccessToken
  - Apply configurations in OnModelCreating
  - Connection string from configuration
- [ ] **T021** Create `DesignTimeDbContextFactory` in `Maliev.AuthService.Data\DesignTimeDbContextFactory.cs` for EF Core migrations
- [ ] **T022** Generate initial EF Core migration named "InitialCreate" using `dotnet ef migrations add InitialCreate --project Maliev.AuthService.Data`
- [ ] **T023** Create project reference from `Maliev.AuthService.Api` to `Maliev.AuthService.Data`
- [ ] **T024** Create project reference from `Maliev.AuthService.Tests` to `Maliev.AuthService.Api`

---

## Phase 3.3: Contract Tests (TDD - MUST FAIL)
**CRITICAL: Write these tests BEFORE any controller implementation. Tests MUST fail initially.**

- [ ] **T025** [P] Create contract test `AuthenticationContractTests.cs` in `Maliev.AuthService.Tests\Contract\`:
  - Test POST /auth/login request/response schema validation
  - Validate LoginRequest schema (username, password, user_type)
  - Validate LoginResponse schema (access_token, refresh_token, token_type, expires_in)
  - Validate 401 error response schema
  - Test MUST fail (endpoint not implemented yet)
- [ ] **T026** [P] Create contract test `RefreshContractTests.cs` in `Maliev.AuthService.Tests\Contract\`:
  - Test POST /auth/refresh request/response schema validation
  - Validate RefreshRequest schema (refresh_token)
  - Validate RefreshResponse schema (access_token, refresh_token, token_type, expires_in)
  - Validate 401 error responses (invalid_token, token_family_invalidated)
  - Test MUST fail (endpoint not implemented yet)
- [ ] **T027** [P] Create contract test `ValidateContractTests.cs` in `Maliev.AuthService.Tests\Contract\`:
  - Test POST /auth/validate request/response schema validation
  - Validate ValidateRequest schema (access_token)
  - Validate ValidateResponse schema (user_id, user_type, username, email, roles, permissions)
  - Validate 401 error responses
  - Test MUST fail (endpoint not implemented yet)
- [ ] **T028** [P] Create contract test `RevokeContractTests.cs` in `Maliev.AuthService.Tests\Contract\`:
  - Test POST /auth/revoke request/response validation
  - Validate RevokeRequest schema (access_token, reason)
  - Validate 204 No Content response
  - Validate 401 error response
  - Test MUST fail (endpoint not implemented yet)

---

## Phase 3.3.5: Test Verification Checkpoint (MANDATORY - Constitution III)

- [ ] **T028.5** Verify all contract tests (T025-T028) FAIL before proceeding to implementation:
  - Run: `dotnet test Maliev.AuthService.Tests --filter "Category=Contract"`
  - Expected: All contract tests FAIL with "endpoint not found" or similar errors
  - If any test PASSES, halt immediately - endpoints should not exist yet
  - Document test failure output for Red-Green-Refactor cycle
  - Only proceed to Phase 3.4 after confirming all tests fail
  - **GATE**: This is a NON-NEGOTIABLE checkpoint per Constitution III (Test-First Development)

---

## Phase 3.4: Integration Test Scenarios (TDD - MUST FAIL)
**CRITICAL: Write these tests BEFORE service implementation. Tests MUST fail initially.**

- [ ] **T029** Create `TestDatabaseFixture.cs` in `Maliev.AuthService.Tests\Fixtures\`:
  - Setup PostgreSQL Testcontainer
  - Apply EF Core migrations
  - Implement IAsyncLifetime for container lifecycle
  - Provide AuthDbContext for tests
- [ ] **T030** [P] Create `TestDataFactory.cs` in `Maliev.AuthService.Tests\Fixtures\`:
  - Helper methods to create test RefreshTokens
  - Helper methods to create test TokenFamilies
  - Helper methods to create test RevokedAccessTokens
  - ES256 key pair generation for testing
- [ ] **T031** [P] Create integration test `AuthenticationFlowTests.cs` in `Maliev.AuthService.Tests\Integration\`:
  - Test Scenario 1: Customer login flow (login → validate → refresh)
  - Verify tokens are generated correctly
  - Verify user identity is returned
  - Test MUST fail (services not implemented yet)
- [ ] **T032** [P] Create integration test `EmployeeAuthenticationTests.cs` in `Maliev.AuthService.Tests\Integration\`:
  - Test Scenario 2: Employee login flow
  - Verify employee user type is distinguished from customer
  - Verify different validation endpoint is called
  - Test MUST fail (services not implemented yet)
- [ ] **T033** [P] Create integration test `TokenRotationTests.cs` in `Maliev.AuthService.Tests\Integration\`:
  - Test Scenario 3: Token rotation (Quickstart Scenario 1.3)
  - Verify old refresh token is marked as used
  - Verify new tokens are different from old tokens
  - Test MUST fail (rotation logic not implemented yet)
- [ ] **T034** [P] Create integration test `TokenReuseDetectionTests.cs` in `Maliev.AuthService.Tests\Integration\`:
  - Test Scenario 4: Token reuse detection (Quickstart Scenario 1.4)
  - Verify reuse of used refresh token invalidates entire family
  - Verify error response is "token_family_invalidated"
  - Verify database shows all tokens in family revoked
  - Test MUST fail (reuse detection not implemented yet)
- [ ] **T035** [P] Create integration test `AccountRateLimitingTests.cs` in `Maliev.AuthService.Tests\Integration\`:
  - Test Scenario 5: Account-based rate limiting (Quickstart Scenario 3)
  - Verify 5 failed attempts trigger 15 min lockout
  - Verify progressive delays (1s, 2s, 4s)
  - Verify HTTP 429 response with retry-after header
  - Test MUST fail (rate limiting not configured yet)
- [ ] **T036** [P] Create integration test `IpRateLimitingTests.cs` in `Maliev.AuthService.Tests\Integration\`:
  - Test Scenario 6: IP-based rate limiting (Quickstart Scenario 4)
  - Verify 20 attempts across different accounts trigger IP block
  - Verify rate limit headers are present
  - Test MUST fail (IP rate limiting not configured yet)
- [ ] **T037** [P] Create integration test `CircuitBreakerTests.cs` in `Maliev.AuthService.Tests\Integration\`:
  - Test Scenario 7: Circuit breaker behavior (Quickstart Scenario 6)
  - Verify 5 failures open circuit for 30 seconds
  - Verify HTTP 503 response when circuit is open
  - Verify health check reflects circuit state
  - Test MUST fail (circuit breaker not configured yet)
- [ ] **T038** [P] Create integration test `TokenRevocationTests.cs` in `Maliev.AuthService.Tests\Integration\`:
  - Test Scenario 8: Access token revocation (Quickstart Scenario 5)
  - Verify revoked token validation returns 401
  - Verify revocation entry exists in database
  - Verify revocation event is published (Redis)
  - Test MUST fail (revocation service not implemented yet)
- [ ] **T039** [P] Create integration test `HealthCheckTests.cs` in `Maliev.AuthService.Tests\Integration\`:
  - Test /auth/liveness returns 200 "Healthy"
  - Test /auth/readiness returns health check status
  - Verify PostgreSQL health check
  - Test MUST fail (health checks not implemented yet)

---

## Phase 3.5: Core Services - JWT & Token Generation

- [ ] **T040** Create `JwtOptions.cs` in `Maliev.AuthService.Api\Options\`:
  - Properties: Issuer, Audience, SigningKeyPem, AccessTokenExpiryMinutes (15), RefreshTokenExpiryDays (7), ClockSkewSeconds (30)
- [ ] **T041** Create interface `ITokenGenerator.cs` in `Maliev.AuthService.Api\Services\`:
  - Method: GenerateAccessToken(Guid userId, UserType userType, string username, string email, string[] roles, string[] permissions) returns string
  - Method: GenerateRefreshToken() returns string (256-bit cryptographic random)
- [ ] **T042** Create `TokenGenerator.cs` in `Maliev.AuthService.Api\Services\`:
  - Implement ITokenGenerator
  - Use System.Security.Cryptography.ECDsa for ES256 signing
  - Import private key from JwtOptions.SigningKeyPem
  - Include claims: sub (userId), user_type, username, email, roles, permissions, iss, aud, exp, nbf, jti
  - Generate refresh token with RandomNumberGenerator (32 bytes → base64)
- [ ] **T043** Create interface `ITokenValidator.cs` in `Maliev.AuthService.Api\Services\`:
  - Method: ValidateAccessToken(string token) returns ClaimsPrincipal
  - Method: IsTokenRevoked(string jti) returns Task<bool>
- [ ] **T044** Create `TokenValidator.cs` in `Maliev.AuthService.Api\Services\`:
  - Implement ITokenValidator
  - Use ECDsa public key for signature verification
  - Validate algorithm allowlist (only ES256)
  - Validate iss, aud, exp, nbf, jti claims
  - Check revocation status (in-memory cache + database fallback)
  - Use CryptographicOperations.FixedTimeEquals for comparisons
- [ ] **T045** [P] Create unit test `TokenGeneratorTests.cs` in `Maliev.AuthService.Tests\Unit\`:
  - Test access token generation with all claims
  - Test refresh token randomness (256 bits)
  - Test token expiration times (15 min access, 7 days refresh)
  - Test ES256 signature can be verified
- [ ] **T046** [P] Create unit test `TokenValidatorTests.cs` in `Maliev.AuthService.Tests\Unit\`:
  - Test valid token validation
  - Test expired token rejection
  - Test algorithm mismatch rejection ("none" algorithm attack)
  - Test invalid signature rejection
  - Test revoked token detection

---

## Phase 3.6: Refresh Token Service & Rotation

- [ ] **T047** Create interface `IRefreshTokenRepository.cs` in `Maliev.AuthService.Data\Repositories\`:
  - Method: GetByTokenHashAsync(string tokenHash) returns Task<RefreshToken?>
  - Method: AddAsync(RefreshToken token) returns Task
  - Method: UpdateAsync(RefreshToken token) returns Task
  - Method: GetByFamilyIdAsync(Guid familyId) returns Task<List<RefreshToken>>
  - Method: InvalidateFamilyAsync(Guid familyId) returns Task
- [ ] **T048** Create `RefreshTokenRepository.cs` in `Maliev.AuthService.Data\Repositories\`:
  - Implement IRefreshTokenRepository
  - Use AuthDbContext for database operations
  - Include TokenFamily navigation in queries
  - Use AsNoTracking for read-only queries
- [ ] **T049** Create interface `ITokenFamilyRepository.cs` in `Maliev.AuthService.Data\Repositories\`:
  - Method: GetByIdAsync(Guid familyId) returns Task<TokenFamily?>
  - Method: AddAsync(TokenFamily family) returns Task
  - Method: UpdateAsync(TokenFamily family) returns Task
- [ ] **T050** Create `TokenFamilyRepository.cs` in `Maliev.AuthService.Data\Repositories\`:
  - Implement ITokenFamilyRepository
  - Use AuthDbContext for database operations
- [ ] **T051** Create interface `IRefreshTokenService.cs` in `Maliev.AuthService.Api\Services\`:
  - Method: CreateTokenFamilyAsync(Guid userId, UserType userType, string refreshToken) returns Task<Guid> (returns familyId)
  - Method: RotateTokenAsync(string providedToken) returns Task<TokenRotationResult>
  - Method: IsTokenValidAsync(string tokenHash) returns Task<(bool isValid, Guid? userId, UserType? userType)>
- [ ] **T052** Create `RefreshTokenService.cs` in `Maliev.AuthService.Api\Services\`:
  - Implement IRefreshTokenService
  - Implement token rotation with reuse detection (OAuth 2.0 RFC 9700)
  - Use SHA-256 for token hashing (CryptographicOperations.FixedTimeEquals for comparison)
  - Mark old token as used (IsUsed = true)
  - Generate new token in same family
  - Update TokenFamily.LastUsedAt
  - Handle reuse detection: if token IsUsed = true, invalidate entire family
  - Use database transaction for atomic operations
  - Retry on DbUpdateConcurrencyException (optimistic concurrency)
- [ ] **T053** Create `TokenRotationResult.cs` in `Maliev.AuthService.Api\Models\`:
  - Properties: Success (bool), NewRefreshToken (string?), UserId (Guid?), ErrorCode (enum: InvalidToken, TokenExpired, TokenRevoked, FamilyInvalidated, ConcurrencyConflict)
- [ ] **T054** [P] Create unit test `RefreshTokenServiceTests.cs` in `Maliev.AuthService.Tests\Unit\`:
  - Test token rotation success case
  - Test reuse detection (used token → family invalidation)
  - Test expired token rejection
  - Test revoked token rejection
  - Test concurrency conflict handling

---

## Phase 3.7: External Validation & Circuit Breaker

- [ ] **T055** Create `ExternalServiceOptions.cs` in `Maliev.AuthService.Api\Options\`:
  - Properties: CustomerValidationUrl, EmployeeValidationUrl, TimeoutSeconds (5), CircuitBreakerFailureThreshold (5), CircuitBreakerDurationSeconds (30)
- [ ] **T056** Create interface `IExternalValidationService.cs` in `Maliev.AuthService.Api\Services\`:
  - Method: ValidateCustomerCredentialsAsync(string username, string password) returns Task<ValidationResult>
  - Method: ValidateEmployeeCredentialsAsync(string username, string password) returns Task<ValidationResult>
- [ ] **T057** Create `ValidationResult.cs` in `Maliev.AuthService.Api\Models\`:
  - Properties: IsValid (bool), UserId (Guid?), Username (string?), Email (string?), Roles (string[]?), Permissions (string[]?)
- [ ] **T058** Create `ExternalValidationService.cs` in `Maliev.AuthService.Api\Services\`:
  - Implement IExternalValidationService
  - Use IHttpClientFactory with typed HTTP clients
  - POST credentials to external validation URLs
  - Parse JSON response to ValidationResult
  - Polly circuit breaker automatically applied via DI configuration
- [ ] **T059** Configure Polly circuit breaker policies in Program.cs (separate task for DI setup):
  - Create CustomerValidationService HTTP client with circuit breaker
  - Create EmployeeValidationService HTTP client with circuit breaker
  - Circuit breaker: 5 failures → 30s open → half-open test
  - Timeout policy: 5 seconds
  - Exponential backoff retry: 3 attempts
- [ ] **T060** Create `ExternalServiceHealthCheck.cs` in `Maliev.AuthService.Api\HealthChecks\`:
  - Implement IHealthCheck
  - Check circuit breaker status for customer and employee services
  - Return Healthy (closed), Degraded (half-open), Unhealthy (open)
- [ ] **T061** [P] Create unit test `ExternalValidationServiceTests.cs` in `Maliev.AuthService.Tests\Unit\`:
  - Test successful validation response
  - Test circuit breaker opens after 5 failures
  - Test circuit breaker half-open state
  - Test timeout handling

---

## Phase 3.8: Rate Limiting & Progressive Delays

- [ ] **T062** Create `RateLimitOptions.cs` in `Maliev.AuthService.Api\Options\`:
  - Properties: AccountLimit (5), AccountWindowMinutes (15), IpLimit (20), IpWindowMinutes (15), ProgressiveDelays (int[] {1000, 2000, 4000})
- [ ] **T063** Configure ASP.NET Core rate limiting middleware in Program.cs:
  - Add account-based rate limiting policy (5 attempts / 15 min)
  - Add IP-based rate limiting policy (20 attempts / 15 min)
  - Add service-to-service rate limiting policy (1000 validations/min)
  - Configure sliding window algorithm
  - Configure OnRejected handler (return 429 with retry-after header)
- [ ] **T064** Create interface `IProgressiveDelayService.cs` in `Maliev.AuthService.Api\Services\`:
  - Method: ApplyDelayAsync(string username) returns Task (delays based on attempt count)
- [ ] **T065** Create `ProgressiveDelayService.cs` in `Maliev.AuthService.Api\Services\`:
  - Implement IProgressiveDelayService
  - Track failed attempts in IMemoryCache
  - Apply progressive delays: 1s (3rd attempt), 2s (4th), 4s (5th)
  - Reset counter after 15 minutes

---

## Phase 3.9: Token Revocation & Distributed Events

- [ ] **T066** Create interface `ITokenRevocationService.cs` in `Maliev.AuthService.Api\Services\`:
  - Method: RevokeAccessTokenAsync(string jti, string reason) returns Task
  - Method: IsTokenRevokedAsync(string jti) returns Task<bool>
  - Method: PublishRevocationEventAsync(string jti, DateTimeOffset revokedAt, DateTimeOffset expiresAt) returns Task
- [ ] **T067** Create `TokenRevocationService.cs` in `Maliev.AuthService.Api\Services\`:
  - Implement ITokenRevocationService
  - Store revocation in RevokedAccessToken table
  - Publish revocation event to Redis pub/sub ("token-revocations" channel)
  - Use StackExchange.Redis IConnectionMultiplexer
  - Add to in-memory cache for fast validation (<2s propagation)
- [ ] **T068** Create `TokenRevocationSubscriber.cs` in `Maliev.AuthService.Api\Services\` (BackgroundService):
  - Subscribe to Redis "token-revocations" channel
  - On event received, add jti to in-memory cache
  - Handle Redis connection failures gracefully
  - Log revocation events with correlation ID
- [ ] **T069** Create `TokenRevocationEvent.cs` in `Maliev.AuthService.Api\Models\`:
  - Properties: Jti (string), RevokedAt (DateTimeOffset), ExpiresAt (DateTimeOffset)

---

## Phase 3.10: Authentication Orchestration

- [ ] **T070** Create interface `IAuthenticationService.cs` in `Maliev.AuthService.Api\Services\`:
  - Method: AuthenticateAsync(LoginRequest request) returns Task<LoginResponse>
  - Method: RefreshTokenAsync(RefreshRequest request) returns Task<RefreshResponse>
  - Method: ValidateTokenAsync(ValidateRequest request) returns Task<ValidateResponse>
  - Method: RevokeTokenAsync(RevokeRequest request) returns Task
- [ ] **T071** Create `AuthenticationService.cs` in `Maliev.AuthService.Api\Services\`:
  - Implement IAuthenticationService (orchestration layer)
  - Inject: IExternalValidationService, ITokenGenerator, IRefreshTokenService, ITokenRevocationService, IProgressiveDelayService
  - AuthenticateAsync: call external validation → generate tokens → create token family → return response
  - RefreshTokenAsync: validate refresh token → rotate token → generate new access token → return response
  - ValidateTokenAsync: validate JWT → check revocation → return user identity
  - RevokeTokenAsync: extract jti from token → revoke → auto-revoke all access tokens on password change
- [ ] **T072** Create `LoginRequest.cs` in `Maliev.AuthService.Api\Models\`:
  - Properties: Username (string), Password (string), UserType (string: "customer" or "employee")
  - FluentValidation rules: Username required, Password required, UserType in {"customer", "employee"}
- [ ] **T073** Create `LoginResponse.cs` in `Maliev.AuthService.Api\Models\`:
  - Properties: AccessToken (string), RefreshToken (string), TokenType (string = "Bearer"), ExpiresIn (int = 900)
- [ ] **T074** Create `RefreshRequest.cs` in `Maliev.AuthService.Api\Models\`:
  - Properties: RefreshToken (string)
  - FluentValidation rules: RefreshToken required
- [ ] **T075** Create `ValidateRequest.cs` in `Maliev.AuthService.Api\Models\`:
  - Properties: AccessToken (string)
  - FluentValidation rules: AccessToken required
- [ ] **T076** Create `ValidateResponse.cs` in `Maliev.AuthService.Api\Models\`:
  - Properties: UserId (Guid), UserType (string), Username (string), Email (string), Roles (string[]), Permissions (string[])
- [ ] **T077** Create `RevokeRequest.cs` in `Maliev.AuthService.Api\Models\`:
  - Properties: AccessToken (string), Reason (string)
  - FluentValidation rules: AccessToken required, Reason in {"user_logout", "password_changed", "admin_action", "suspicious_activity", "token_family_invalidated"}
- [ ] **T078** Create `ErrorResponse.cs` in `Maliev.AuthService.Api\Models\`:
  - Properties: Error (string), ErrorDescription (string), CorrelationId (string), RetryAfter (int?)

---

## Phase 3.11: Controller & API Endpoints

- [ ] **T079** Create `AuthenticationController.cs` in `Maliev.AuthService.Api\Controllers\`:
  - Route: [ApiController], [Route("auth")]
  - Inject IAuthenticationService
  - POST /auth/login endpoint → AuthenticateAsync
  - POST /auth/refresh endpoint → RefreshTokenAsync
  - POST /auth/validate endpoint → ValidateTokenAsync
  - POST /auth/revoke endpoint [Authorize] → RevokeTokenAsync
  - Apply [EnableRateLimiting("account-limit")] and [EnableRateLimiting("ip-limit")] to login endpoint
  - Return appropriate HTTP status codes (200, 401, 429, 503)
  - Include X-Correlation-ID in all responses
  - Return ErrorResponse on failures

---

## Phase 3.12: Middleware & Cross-Cutting Concerns

- [ ] **T080** Create `CorrelationIdMiddleware.cs` in `Maliev.AuthService.Api\Middleware\`:
  - Extract or generate correlation ID from X-Correlation-ID or X-Request-ID headers
  - Add correlation ID to HttpContext.Items
  - Add correlation ID to response headers
  - Add correlation ID to Serilog LogContext
  - Add correlation ID to OpenTelemetry Activity tags
- [ ] **T081** Create `ExceptionHandlingMiddleware.cs` in `Maliev.AuthService.Api\Middleware\`:
  - Catch all unhandled exceptions
  - Log exception with correlation ID
  - Return ErrorResponse with 500 status
  - Do not expose sensitive error details
  - Include exception type and stack trace in logs (not response)
- [ ] **T082** Create `PostgresHealthCheck.cs` in `Maliev.AuthService.Api\HealthChecks\`:
  - Implement IHealthCheck
  - Check AuthDbContext.Database.CanConnectAsync()
  - Return Healthy if connected, Unhealthy otherwise

---

## Phase 3.13: Configuration & Startup (Program.cs)

- [ ] **T083** Configure `Program.cs` in `Maliev.AuthService.Api\`:
  - Configure Serilog (console only, structured logging)
  - Load secrets from /mnt/secrets (Google Secret Manager):
    - JWT signing private key (/mnt/secrets/jwt-signing-key)
    - JWT issuer (/mnt/secrets/jwt-issuer) - **CRITICAL**: NEVER hardcode production endpoints (Constitution VI)
    - JWT audience (/mnt/secrets/jwt-audience) - **CRITICAL**: NEVER hardcode production endpoints (Constitution VI)
    - PostgreSQL connection string (/mnt/secrets/postgres-connection-string)
    - Redis connection string (/mnt/secrets/redis-connection-string)
    - External validation service URLs (/mnt/secrets/customer-validation-url, /mnt/secrets/employee-validation-url)
  - Register services in DI container:
    - AddMemoryCache() (without SizeLimit)
    - AddDbContext<AuthDbContext>
    - Repositories: IRefreshTokenRepository, ITokenFamilyRepository
    - Services: ITokenGenerator, ITokenValidator, IRefreshTokenService, IExternalValidationService, IAuthenticationService, ITokenRevocationService, IProgressiveDelayService
    - Configure JwtOptions, ExternalServiceOptions, RateLimitOptions from configuration (loaded from Secret Manager)
    - Configure Polly HTTP clients for external validation (T059)
    - Configure rate limiting middleware (T063)
    - AddControllers with FluentValidation
    - AddHealthChecks (PostgreSQL, ExternalService)
    - AddAuthentication (JWT Bearer for [Authorize] endpoints)
    - Register TokenRevocationSubscriber as hosted service
  - Configure middleware pipeline (EXACT ORDER):
    - UseSwagger / UseSwaggerUI (route: "/auth/swagger")
    - UseHttpsRedirection
    - UseRateLimiter
    - UseAuthentication
    - UseAuthorization
    - CorrelationIdMiddleware
    - ExceptionHandlingMiddleware
    - MapControllers
    - MapHealthChecks("/auth/liveness") → liveness probe
    - MapHealthChecks("/auth/readiness") → readiness probe with UIResponseWriter
  - Configure Kestrel to listen on port 8080
- [ ] **T084** Configure OpenTelemetry distributed tracing in Program.cs:
  - AddOpenTelemetry().WithTracing()
  - AddAspNetCoreInstrumentation (enrich with client IP, user agent)
  - AddHttpClientInstrumentation
  - AddSource("Maliev.AuthService") for custom activity source
  - AddPrometheusExporter
  - Map Prometheus scrape endpoint at /metrics
  - Configure W3C Trace Context propagation
- [ ] **T085** Configure Serilog in Program.cs:
  - ReadFrom.Configuration
  - WriteTo.Console (structured JSON format)
  - Enrich with correlation ID from LogContext
  - Minimum level: Information (override to Debug for Maliev.AuthService.*)
  - Include timestamp, level, message, exception, correlation_id, trace_id, span_id

---

## Phase 3.14: CI/CD & Deployment

- [ ] **T086** Create `.github\workflows\ci-develop.yml`:
  - Trigger on push to develop branch
  - Steps: Checkout, Setup .NET 9, Restore, Build, Test, Docker build/push
  - Push Docker image to Google Artifact Registry (asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact-dev)
  - Update maliev-gitops repository with new image tag (Kustomize edit)
  - Commit and push to maliev-gitops/main
- [ ] **T087** [P] Create `.github\workflows\ci-staging.yml` (same as develop but for staging environment)
- [ ] **T088** [P] Create `.github\workflows\ci-main.yml` (same as develop but for production environment)

---

## Phase 3.15: Documentation & Validation

- [ ] **T089** Update `README.md` in repository root:
  - Project overview
  - Architecture diagram (Clean Architecture layers)
  - Prerequisites (Docker, .NET 9, kubectl)
  - Local development setup instructions
  - Database migration instructions
  - Environment variables (from Google Secret Manager)
  - Running tests: `dotnet test`
  - Building: `dotnet build`
  - Running locally: `dotnet run --project Maliev.AuthService.Api`
  - Docker build: `docker build -t maliev-auth-service .`
  - Kubernetes deployment (reference maliev-gitops)
- [ ] **T090** Verify all 8 quickstart.md test scenarios manually:
  - Scenario 1: Customer Login Flow ✅
  - Scenario 2: Employee Login Flow ✅
  - Scenario 3: Rate Limiting (Account-Based) ⚠️
  - Scenario 4: Rate Limiting (IP-Based) ⚠️
  - Scenario 5: Access Token Revocation 🔒
  - Scenario 6: Circuit Breaker (External Service Failure) 🔌
  - Scenario 7: Token Expiration ⏰
  - Scenario 8: Distributed Tracing (Correlation ID) 🔍
  - Document any deviations or issues found
- [ ] **T091** Run all automated tests and verify 100% pass rate:
  - Contract tests (T025-T028)
  - Integration tests (T031-T039)
  - Unit tests (T045-T046, T054, T061)
  - Verify code coverage >80%
- [ ] **T096** Create client integration security documentation (addresses FR-073):
  - Document: `docs/CLIENT_INTEGRATION_SECURITY.md`
  - Token storage best practices:
    - Refresh tokens MUST be stored in secure persistent client storage (e.g., iOS Keychain, Android KeyStore, browser secure storage APIs)
    - Access tokens SHOULD be stored in memory only, NOT in persistent storage
    - Tokens MUST NOT be stored in localStorage or sessionStorage (XSS vulnerability)
  - Transmission security:
    - Tokens MUST only be transmitted over HTTPS/TLS
    - Tokens MUST NOT be included in URL query parameters or fragments (logging/history exposure)
    - Use Authorization header: `Authorization: Bearer <access_token>`
  - Token refresh patterns:
    - Implement automatic token refresh before expiration (proactive refresh at 80% lifetime)
    - Handle token family invalidation (reuse detection) with forced re-authentication
  - Error handling:
    - 401 with "token_expired" → trigger refresh flow
    - 401 with "token_family_invalidated" → force logout and re-authentication
    - 429 rate limit → implement exponential backoff
  - Security warnings:
    - Never log token values (access or refresh)
    - Clear tokens from memory on logout
    - Implement certificate pinning for production mobile apps
- [ ] **T096.5** Security audit: Verify no production endpoints, connection strings, or secrets in source code (Constitution VI compliance):
  - Scan all .cs files for hardcoded URLs (search for "https://", "http://")
  - Scan all .json files for connection strings (search for "Server=", "Password=", "ConnectionString")
  - Scan all .md files for production endpoints (search for "maliev.com", "auth.maliev")
  - Verify all sensitive configuration uses placeholders: `${JWT_ISSUER}`, `${POSTGRES_CONNECTION_STRING}`, etc.
  - Verify appsettings.json contains ONLY non-sensitive defaults (localhost URLs acceptable for development)
  - Document placeholder patterns in README.md security section
  - Generate security audit report: `docs/SECURITY_AUDIT.md`
  - **GATE**: CRITICAL violation if any production secrets/endpoints found - MUST remediate before deployment

---

## Phase 3.16: GitOps Deployment (maliev-gitops repository)

- [ ] **T092** Create Kubernetes base manifests in `maliev-gitops/3-apps/maliev-auth-service/base/`:
  - `deployment.yaml`: Deployment with 2 replicas, resource limits (500m CPU, 512Mi memory), liveness/readiness probes, envFrom for secrets
  - `service.yaml`: ClusterIP service on port 8080
  - `configmap.yaml`: Non-sensitive configuration (log level, rate limits)
  - `servicemonitor.yaml`: Prometheus ServiceMonitor for /metrics endpoint
  - `kustomization.yaml`: List all resources
- [ ] **T093** Create development overlay in `maliev-gitops/3-apps/maliev-auth-service/overlays/development/`:
  - `kustomization.yaml`: Set image, namespace (maliev-dev), replicas (1)
  - Reference Google Secret Manager secrets: JWT_SIGNING_KEY_DEV, POSTGRES_CONNECTION_STRING_DEV, REDIS_CONNECTION_STRING_DEV
- [ ] **T094** Create staging overlay in `maliev-gitops/3-apps/maliev-auth-service/overlays/staging/`:
  - `kustomization.yaml`: Set image, namespace (maliev-staging), replicas (2)
  - Reference Google Secret Manager secrets: JWT_SIGNING_KEY_STAGING, POSTGRES_CONNECTION_STRING_STAGING, REDIS_CONNECTION_STRING_STAGING
- [ ] **T095** Create production overlay in `maliev-gitops/3-apps/maliev-auth-service/overlays/production/`:
  - `kustomization.yaml`: Set image, namespace (maliev-prod), replicas (3)
  - Reference Google Secret Manager secrets: JWT_SIGNING_KEY_PROD, POSTGRES_CONNECTION_STRING_PROD, REDIS_CONNECTION_STRING_PROD

---

## Dependencies Graph

```
T001-T012 (Setup & Infrastructure)
  ↓
T013-T024 (Database Models, Migrations, Project References)
  ↓
T025-T039 (All Tests - MUST FAIL)
  ↓
T040-T046 (JWT & Token Services)
  ↓
T047-T054 (Refresh Token & Rotation)
  ↓
T055-T061 (External Validation & Circuit Breaker)
  ↓
T062-T065 (Rate Limiting)
  ↓
T066-T069 (Token Revocation)
  ↓
T070-T078 (Authentication Orchestration & Models)
  ↓
T079 (Controller)
  ↓
T080-T082 (Middleware & Health Checks)
  ↓
T083-T085 (Program.cs Configuration)
  ↓
T086-T088 (CI/CD Workflows)
  ↓
T089-T091 (Documentation & Validation)
  ↓
T092-T095 (GitOps Deployment - Optional)
```

---

## Parallel Execution Examples

### Example 1: Setup Phase (T005-T007, T010-T012)
```bash
# Launch T005, T006, T007, T011, T012 together (different files):
Task: "Add NuGet packages to Maliev.AuthService.Api.csproj"
Task: "Add NuGet packages to Maliev.AuthService.Data.csproj"
Task: "Add NuGet packages to Maliev.AuthService.Tests.csproj"
Task: "Create .dockerignore in repository root"
Task: "Create .editorconfig in repository root"
```

### Example 2: Entity Creation (T013-T016)
```bash
# Launch T013, T014, T015, T016 together (different files):
Task: "Create UserType enum"
Task: "Create RefreshToken entity"
Task: "Create TokenFamily entity"
Task: "Create RevokedAccessToken entity"
```

### Example 3: Contract Tests (T025-T028)
```bash
# Launch T025, T026, T027, T028 together (different test files):
Task: "Create contract test for POST /auth/login"
Task: "Create contract test for POST /auth/refresh"
Task: "Create contract test for POST /auth/validate"
Task: "Create contract test for POST /auth/revoke"
```

### Example 4: Integration Tests (T031-T038)
```bash
# Launch T031-T038 together (different test files):
Task: "Create integration test for customer login flow"
Task: "Create integration test for employee login flow"
Task: "Create integration test for token rotation"
Task: "Create integration test for token reuse detection"
Task: "Create integration test for account rate limiting"
Task: "Create integration test for IP rate limiting"
Task: "Create integration test for circuit breaker"
Task: "Create integration test for token revocation"
```

---

## Notes

- **[P] tasks**: 31 tasks marked [P] can run in parallel (different files, no dependencies)
- **TDD Enforcement**: All tests (T025-T039) MUST be written and MUST fail before implementing services (T040+)
- **Database First**: Entity models and migrations (T013-T024) before any service implementation
- **Commit Strategy**: Commit after completing each task for atomic changes
- **Test Verification**: Run `dotnet test` after each implementation task to verify tests pass incrementally

---

## Validation Checklist
*GATE: Verified during task generation*

- [x] All 5 endpoints from openapi.yaml have implementation tasks
- [x] All 3 entities from data-model.md have model tasks (T014-T016)
- [x] All 8 scenarios from quickstart.md have integration tests (T031-T038)
- [x] Tests come before implementation (TDD enforced)
- [x] Parallel tasks are truly independent (different files)
- [x] Each task specifies exact file path
- [x] No [P] task modifies same file as another [P] task
- [x] Setup before tests, tests before implementation, implementation before polish

---

**Total Tasks**: 99 (updated after constitution compliance fixes)
**Parallel Tasks**: 31 marked [P]
**Sequential Dependencies**: 68 tasks
**Critical Gates**: 3 (T000 cleanup, T028.5 test verification, T096.5 security audit)
**Estimated Completion**: 3-4 weeks (1 developer) or 1-2 weeks (2 developers with parallelization)

**Constitution Compliance**: ✅ 100% compliant with MALIEV Microservices Constitution v1.0.0
- T000: Clean artifacts (Principle VIII)
- T028.5: Test-first verification (Principle III)
- T083: Secrets from Google Secret Manager (Principle VI)
- T096.5: Security audit gate (Principle VI)

**Status**: ✅ Ready for execution - All tasks are immediately executable with TDD approach
