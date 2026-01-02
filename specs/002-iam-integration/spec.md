# Feature Specification: AuthService IAM Integration

**Feature Branch**: `002-iam-integration`  
**Created**: 2025-12-21  
**Status**: Draft  
**Input**: User description: "Modify the AuthService to integrate with the IAM service for permission resolution. The AuthService will continue to handle authentication but will delegate authorization concerns to the IAM service and embed permissions array in JWT token."

## Clarifications

### Session 2025-12-21
- Q: How should the AuthService handle caching of the permissions resolved from the IAM service? → A: No Caching (Fresh Resolution); every login/refresh calls IAM.
- Q: Should the AuthService include user roles in the JWT token in addition to permissions? → A: Include both "permissions" and "roles" claims in the JWT.
- Q: What should be the behavior if the upstream identity source (Customer/Employee) has not yet been migrated to provide a principal_id? → A: Fallback to existing userId (Migration Mode).
- Q: Should permissions be re-resolved from IAM during every token refresh operation? → A: Refresh every time (Force Resolution).
- Q: Should the IAM integration apply to both human users and service-to-service authentication? → A: Both (Users and Services) - Resolve permissions for all authenticated principals.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Secure Permission-Aware Token Issuance (Priority: P1)

As a client application, I want my users to receive JWT tokens that include their assigned permissions and roles from the IAM service, so that I can perform fine-grained authorization checks without calling the IAM service myself.

**Why this priority**: Core objective of the feature. Enables the platform to move towards a centralized authorization model where permissions and roles are carried within the security context (JWT).

**Independent Test**: Can be tested by performing a successful login when the IAM integration is enabled and verifying that the returned JWT contains "permissions" and "roles" claims with the expected values for that principal.

**Acceptance Scenarios**:

1. **Given** a user with assigned permissions and roles in IAM, **When** they log in with IAM integration enabled, **Then** the AuthService returns a JWT containing all resolved permissions and roles in their respective claim arrays.
2. **Given** a successful authentication, **When** the JWT is generated, **Then** the "sub" claim must contain the `principal_id` provided by the upstream identity source (Customer/Employee service).

---

### User Story 2 - Resilient Authentication with IAM Fallback (Priority: P1)

As a system owner, I want the AuthService to remain functional even if the IAM service is slow or unavailable, so that user login is not blocked by downstream authorization failures.

**Why this priority**: Critical for system availability. Authorization resolution is secondary to authentication; users should still be able to enter the system even if they have minimal permissions temporarily.

**Independent Test**: Can be tested by simulating a timeout or 500 error from the IAM service during login and verifying that the AuthService still issues a valid JWT with an empty permissions list.

### Acceptance Scenarios

1. **Given** the IAM service is unavailable or times out (200ms), **When** a user attempts to log in, **Then** the AuthService must still issue a valid JWT with an empty permissions array.
2. **Given** the IAM service consistently fails, **When** the circuit breaker threshold is met, **Then** subsequent login attempts should skip the IAM call and immediately issue tokens with empty permissions until the circuit closes.

### Edge Cases

- **Large Permission Sets**: What happens when a user has a very high number of permissions? (Assumption: The system will embed all resolved permissions, but token size must be monitored to avoid exceeding HTTP header limits).
- **Principal Not Found in IAM**: How does the system handle a principal that authenticated successfully but is unknown to IAM? (Assumption: Treated as "success with zero permissions").
- **Identity Provider Migration**: What if the upstream provider hasn't provided a `principal_id` yet? (Assumption: The system will fall back to using the existing `userId` as the `principal_id` for IAM resolution and JWT `sub` claim during the migration period).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST provide a client to communicate with the IAM service's permission resolution endpoint.
- FR-002**: System MUST resolve permissions and roles for all authenticated principals (Users and Services) using their `principal_id` (or `userId` fallback) from the identity validation response.
- **FR-003**: System MUST embed resolved permissions and roles into the JWT access token as multi-value "permissions" and "roles" claims.
- **FR-004**: System MUST use the `principal_id` as the "sub" (subject) claim in the generated JWT.
- **FR-005**: System MUST implement a timeout of 200ms for all IAM permission resolution calls.
- **FR-006**: System MUST implement a circuit breaker that opens after 5 consecutive failures to the IAM service.
- **FR-008**: System MUST record audit logs for all IAM permission resolution attempts, including latency and success/failure status.
- **FR-009**: System MUST support a service account token for authenticating its calls to the IAM service.
- **FR-010**: System MUST NOT cache permission resolution results locally, ensuring fresh resolution from IAM for every login or token refresh attempt.

### Key Entities *(include if feature involves data)*

- **Principal**: The authenticated identity (User/Service) for which permissions and roles are being resolved.
- **Permission**: A string identifier representing a specific action or resource access right resolved from IAM (e.g., `invoice.read`).
- **Role**: A string identifier representing a group of permissions or a job function resolved from IAM (e.g., `accountant`).
- **IAM Integration Feature Flag**: A configuration setting that controls whether the authorization delegation logic is active.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: User login completion (including permission resolution) takes less than 200ms (P95) when the feature is enabled.
- **SC-002**: 100% of logins succeed even if the IAM service is unavailable (falling back to empty permissions).
- **SC-003**: 100% of JWT tokens contain the expected permission claims when the feature is enabled and IAM returns data.
 - SC-004**: System administrators can perform a configuration change to disable the IAM integration in under 30 seconds (excluding deployment pipeline duration).
- **SC-005**: JWT token size remains under 8KB for users with up to 100 permissions.