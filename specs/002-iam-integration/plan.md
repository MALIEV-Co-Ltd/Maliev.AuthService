# Implementation Plan: AuthService IAM Integration

**Branch**: `002-iam-integration` | **Date**: 2025-12-21 | **Spec**: [specs/002-iam-integration/spec.md]
**Input**: Feature specification from `specs/002-iam-integration/spec.md`

## Summary

This feature integrates AuthService with a downstream IAM service to resolve permissions and roles for authenticated principals. These authorization claims are then embedded in the JWT access token. The implementation prioritizes resilience (fail-safe with empty permissions) and controlled rollout (feature toggle).

## Technical Context

**Language/Version**: .NET 10.0
**Primary Dependencies**: ASP.NET Core, Microsoft.Extensions.Http.Resilience (Polly v8)
**Storage**: N/A (Stateless resolution)
**Testing**: xUnit, Testcontainers (for integration tests mocking IAM)
**Target Platform**: Linux (Dockerized)
**Project Type**: Multi-project .NET Solution (Api, Data, Tests)
**Performance Goals**: < 200ms p95 for login including IAM call
**Constraints**: Zero local caching for permissions; must support legacy `userId` as `principal_id`.

## Constitution Check

- [x] **Service Autonomy**: Self-contained integration logic.
- [x] **Explicit Contracts**: OpenAPI contract for IAM interaction defined in `/contracts/`.
- [x] **Test-First Development**: TDD approach for IAM client and service integration.
- [x] **Real Infrastructure Testing**: Testcontainers used for integration tests.
- [x] **Auditability**: JSON logging for all IAM calls.
- [x] **Security**: Bearer token auth for IAM; no secrets in code.
- [x] **Zero Warnings**: Mandatory build compliance.
- [x] **Clean Artifacts**: Standard project structure.
- [x] **Docker Best Practices**: No changes to existing Dockerfile needed.
- [x] **No AutoMapper/FluentValidation/FluentAssertions**: Using explicit mapping and standard .NET validation.

## Phase 0: Outline & Research
Completed. See `specs/002-iam-integration/research.md`.

## Phase 1: Design & Contracts
Completed.
- Data Model: `specs/002-iam-integration/data-model.md`
- Contracts: `specs/002-iam-integration/contracts/iam-service.yaml`
- Quickstart: `specs/002-iam-integration/quickstart.md`

## Phase 2: Implementation Phases

### Phase 2.1: IAM Client Service
**Goal**: Implement the HTTP client for IAM communication.
- Create `IIAMClient` and `IAMClient`.
- Use `IHttpClientFactory` with `AddStandardResilienceHandler`.
- Implement `ResolvePermissionsAsync` with 200ms timeout.
- Return empty response on failure/timeout (User Story 2).

### Phase 2.2: TokenGenerator Update
**Goal**: Support embedding permissions and roles in JWT.
- Update `ITokenGenerator.GenerateAccessToken` to accept `IEnumerable<string> permissions` and `IEnumerable<string> roles`.
- Update `GenerateServiceAccessTokenAsync` similarly.
- Ensure `sub` claim uses `principalId`.

### Phase 2.3: AuthenticationService Integration
**Goal**: Orchestrate permission resolution during login/refresh.
- Inject `IIAMClient` into `AuthenticationService`.
- Check `IAMIntegrationEnabled` feature flag.
- Resolve permissions for human users (Login/Refresh) and services.
- Pass resolved claims to `TokenGenerator`.

### Phase 2.4: Configuration & Registration
**Goal**: Wire up the new services.
- Register `IAMClient` in `Program.cs`.
- Configure resilience policies.
- Add configuration sections to `appsettings.json`.

### Phase 2.5: Verification & Monitoring
**Goal**: Ensure quality and observability.
- Unit tests for `IAMClient` (Mocking HTTP).
- Integration tests for Login flow with simulated IAM service.
- Add OpenTelemetry metrics for IAM latency and error rates.

## Success Criteria
- [ ] 100% of unit tests pass.
- [ ] 100% of integration tests pass.
- [ ] Login latency < 200ms P95 with IAM integration.
- [ ] JWT contains "permissions" and "roles" claims when enabled.
- [ ] Fail-safe: Login succeeds with empty claims if IAM is down.