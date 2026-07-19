# Research: AuthService IAM Integration

## Decision: Resilience Pattern for IAM Communication
- **Decision**: Use `Microsoft.Extensions.Http.Resilience` (Polly v8+) with a standard Hedging/Retry/Circuit Breaker strategy.
- **Rationale**: The project already has `Microsoft.Extensions.Http.Resilience` included in `Maliev.AuthService.Api.csproj`. This is the modern, recommended way to handle resilience in .NET 10.0.
- **Alternatives considered**: `Microsoft.Extensions.Http.Polly` (v7 style), but v8 is already a dependency and is more performant.

## Decision: JWT Claim Names
- **Decision**: Use `permissions` and `roles` as claim types.
- **Rationale**: Aligned with specification requirements (FR-003) and industry standards for representing granular access rights and high-level groupings in JWTs.

## Decision: Fallback Mechanism
- **Decision**: Return empty collections on IAM failure or timeout.
- **Rationale**: As per User Story 2, the system must remain functional (fail-safe). Minimal access is better than blocking login entirely, provided the client services can handle the absence of permissions.

## Decision: Authentication for IAM Service
- **Decision**: Bearer token authentication using a service account token provided via configuration (and Google Secret Manager in production).
- **Rationale**: Standard service-to-service authentication pattern. Scalable and secure when integrated with a secret manager.

## Decision: Principal ID Resolution
- **Decision**: Rename `UserId` to `PrincipalId` in `CredentialValidationResult` and `AuthenticationService` logic to align with IAM domain terminology. Implement `userId` fallback as a property getter or during mapping to maintain compatibility.
- **Rationale**: Aligned with FR-002 and FR-004.
