# Tasks: AuthService IAM Integration

**Input**: Design documents from `specs/002-iam-integration/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: TDD approach requested in plan.md.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and basic structure

- [X] T001 Add `Microsoft.Extensions.Http.Resilience` NuGet package to `Maliev.AuthService.Api/Maliev.AuthService.Api.csproj`
- [X] T002 [P] Create `Maliev.AuthService.Api/Models/IAM/PermissionResolutionRequest.cs` (from data-model.md)
- [X] T003 [P] Create `Maliev.AuthService.Api/Models/IAM/PermissionResolutionResponse.cs` (from data-model.md)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T004 Create `Maliev.AuthService.Api/Services/IIAMClient.cs` interface (from plan.md)
- [X] T005 Create `Maliev.AuthService.Api/Services/IAMClient.cs` skeleton implementation
- [X] T006 [P] Update `Maliev.AuthService.Api/appsettings.json` with `ExternalServices:IAM` sections
- [X] T007 [P] Update `Maliev.AuthService.Api/appsettings.Development.json` with local IAM service configuration
- [X] T008 [P] Update `Maliev.AuthService.Api/Models/Response/AuthenticationResult.cs` to include `principal_id` if missing
- [X] T009 Update `Maliev.AuthService.Api/Program.cs` to register `IAMClient` with `AddHttpClient` and `AddStandardResilienceHandler`

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Secure Permission-Aware Token Issuance (Priority: P1) 🎯 MVP

**Goal**: Resolve permissions and roles from IAM and embed them in JWT during login.

**Independent Test**: Perform login, verify JWT contains `permissions` and `roles` claims, and `sub` matches `principal_id`.

### Tests for User Story 1

- [X] T010 [P] [US1] Create unit tests for `IAMClient.ResolvePermissionsAsync` in `Maliev.AuthService.Tests/Unit/IAMClientTests.cs` (mocking HttpClient)
- [X] T011 [P] [US1] Create unit tests for `TokenGenerator.GenerateAccessToken` with permissions in `Maliev.AuthService.Tests/Unit/TokenGeneratorTests.cs`
- [X] T012 [P] [US1] Create integration test for login flow with mocked IAM service in `Maliev.AuthService.Tests/Contract/AuthenticationContractTests.cs`

### Implementation for User Story 1

- [X] T013 [US1] Implement `IAMClient.ResolvePermissionsAsync` in `Maliev.AuthService.Api/Services/IAMClient.cs`
- [X] T014 [US1] Update `ITokenGenerator.cs` and `TokenGenerator.cs` to accept `permissions` and `roles` parameters in `GenerateAccessToken`
- [X] T015 [US1] Update `IAuthenticationService.cs` and `AuthenticationService.cs` to inject `IIAMClient`
- [X] T016 [US1] Implement permission resolution logic in `AuthenticationService.AuthenticateAsync` using `IIAMClient` (including structured audit logging with latency)
- [X] T017 [US1] Implement fallback logic to `userId` if `principal_id` is missing in `AuthenticationService.cs` (Migration Mode)
- [X] T018 [US1] Update `AuthenticationService.AuthenticateAsync` to pass resolved claims to `TokenGenerator`

**Checkpoint**: User Story 1 (MVP) is fully functional and testable.

---

## Phase 4: User Story 2 - Resilient Authentication with IAM Fallback (Priority: P1)

**Goal**: Ensure authentication succeeds even if IAM fails (timeout/error) using fail-safe defaults and circuit breaker.

**Independent Test**: Simulate IAM service failure (e.g., 500 or timeout), verify login still succeeds with a valid JWT and empty permissions.

### Tests for User Story 2

- [X] T019 [P] [US2] Add unit test for IAM failure scenario (returns empty) in `Maliev.AuthService.Tests/Unit/IAMClientTests.cs`
- [X] T020 [P] [US2] Add integration test for login with IAM down in `Maliev.AuthService.Tests/Contract/AuthenticationContractTests.cs`

### Implementation for User Story 2

- [X] T021 [US2] Implement fail-safe `try-catch` and timeout logic in `IAMClient.ResolvePermissionsAsync` to return empty collections on error
- [X] T022 [US2] Configure `AddStandardResilienceHandler` in `Program.cs` for `IAMClient` to include circuit breaker (FR-006)
- [X] T023 [US2] Ensure `AuthenticationService.AuthenticateAsync` handles the empty permissions fallback gracefully

**Checkpoint**: System is now resilient to IAM failures.

---

## Phase 5: User Story 3 - Controlled Rollout via Feature Toggle (Priority: P2)

**Goal**: Toggle IAM integration via configuration flag.

**Independent Test**: Verify login issues standard JWT.

### Tests for User Story 3

- [X] T024 [P] [US3] Add unit test for login with feature flag disabled in `Maliev.AuthService.Tests/Unit/AuthenticationServiceTests.cs`

### Implementation for User Story 3

- [X] T025 [US3] Wrap IAM resolution call in `AuthenticationService.AuthenticateAsync` with feature flag check
- [X] T026 [US3] Ensure audit logs in `AuthenticationService.cs` record when feature is enabled/disabled

**Checkpoint**: Rollout control is fully implemented.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories

- [X] T027 [P] Implement `roles` claim in addition to `permissions` across all token issuance paths
- [X] T028 Implement re-resolution of permissions during `RefreshTokenAsync` in `AuthenticationService.cs`
- [X] T029 [P] Update API documentation in `Program.cs` and `README.md` to reflect new JWT claims
- [X] T030 Add OpenTelemetry business metrics for IAM resolution latency and success/failure rates in `IAMClient.cs`
- [X] T031 Run `quickstart.md` validation to ensure end-to-end functionality
- [X] T032 [P] Validate SC-005: Verify JWT token size remains under 8KB when embedding 100+ permissions

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - starts immediately.
- **Foundational (Phase 2)**: Depends on Phase 1 - BLOCKS all user stories.
- **User Stories (Phase 3+)**: All depend on Phase 2 completion.
- **Polish (Final Phase)**: Depends on all user stories being complete.

### User Story Dependencies

- **User Story 1 (P1)**: Independent after Phase 2.
- **User Story 2 (P1)**: Depends on US1 (IAM Client) but can be implemented in parallel with US1's AuthenticationService integration.
- **User Story 3 (P2)**: Independent after Phase 2, but logically follows US1.

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1 & 2.
2. Complete Phase 3 (US1).
3. Validate JWT contains permissions and roles.

### Incremental Delivery

1. Foundation ready.
2. Add US1 → Permission-aware tokens.
3. Add US2 → Resilience.
4. Add US3 → Feature control.
