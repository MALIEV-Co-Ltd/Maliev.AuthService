# Passkey Authentication Hardening Implementation Plan

> **Tracking:** `MALIEV-Co-Ltd/maliev-ops#2`

## Goal

Close the reachable `Maliev.Web` customer-cookie bypass, then permit passkey sign-in only through a service-authenticated AuthService WebAuthn assertion ceremony that is application-bound, expires, and can be consumed exactly once.

This plan deliberately keeps passkey registration, listing, and deletion unavailable. Existing passkey rows were populated from browser-supplied public keys without attestation verification and therefore cannot be trusted. A later customer-session-scoped registration slice must re-enrol credentials using verified attestation before the feature is exposed in the UI.

## Security invariants

- The browser never supplies a trusted principal ID, email, customer ID, application/audience, return URL after flow creation, or credential public key.
- The Web BFF supplies the fixed `web` application value and calls AuthService with its service identity.
- AuthService binds `application=web` to the configured Web BFF service caller.
- The server-generated assertion options, challenge, RP ID, allowed origins, service caller, application, and expiry are persisted as one ceremony.
- Completion atomically consumes the ceremony before returning an identity; invalid and replayed attempts never return a principal.
- WebAuthn parsing and cryptographic verification use `Fido2` rather than MALIEV-authored cryptography.
- Only credentials marked as produced by a verified registration version are eligible for authentication. Existing rows remain quarantined.
- Web resolves the customer only after AuthService verification, confirms the returned principal matches CustomerService, and uses canonical customer data for the cookie.
- Every failure path is generic, emits no identity cookie, and logs only outcome/correlation metadata.

## Task 1: Web containment regression and fix

**Files**

- Add: `Maliev.Web.Tests/PasskeySignInFlowTests.cs`
- Modify: `Maliev.Web.Bff/Controllers/AuthController.cs`
- Modify: `Maliev.Web.Bff/wwwroot/js/maliev-passkey.js`

**Steps**

1. Add a full HTTP test that obtains a real antiforgery token, posts a victim `PrincipalId` and forged email to `/auth/passkey-sign-in`, and proves the current endpoint issues a cookie (RED).
2. Change the legacy endpoint to return `410 Gone` with `passkey_flow_retired`, without querying CustomerService or issuing a cookie.
3. Remove `PasskeySignInRequest` and `submitPasskeySignIn`; retain only browser assertion helpers needed by the replacement flow.
4. Prove the request remains anonymous and no `__Secure-Maliev.Identity` cookie is emitted (GREEN).
5. Commit the containment slice in `Maliev.Web`.

## Task 2: AuthService containment and authorization

**Files**

- Add: `Maliev.AuthService.Tests/Contract/PasskeyEndpointContainmentTests.cs`
- Modify: `Maliev.AuthService.Api/Controllers/AuthenticationController.cs`
- Modify: `Maliev.AuthService.Api/Authorization/AuthPermissions.cs` only if a canonical existing permission cannot express the boundary

**Steps**

1. Add metadata/HTTP tests proving passkey registration, listing, and deletion cannot invoke `IPasskeyService` and are unavailable to anonymous callers (RED).
2. Require `AuthPermissions.ExchangeIdentities` for authentication begin/complete.
3. Return `503 passkey_registration_unavailable` from register begin/complete/list/delete until verified registration is implemented.
4. Keep the current v1 route names so clients receive an explicit, non-success response instead of silently falling through.
5. Commit the AuthService containment slice.

## Task 3: Persist single-use assertion ceremonies and quarantine old credentials

**Files**

- Add: `Maliev.AuthService.Domain/Entities/PasskeyCeremony.cs`
- Add: `Maliev.AuthService.Infrastructure/Configurations/PasskeyCeremonyConfiguration.cs`
- Modify: `Maliev.AuthService.Domain/Entities/PasskeyCredential.cs`
- Modify: `Maliev.AuthService.Infrastructure/Configurations/PasskeyCredentialConfiguration.cs`
- Modify: `Maliev.AuthService.Infrastructure/DbContexts/AuthDbContext.cs`
- Add: generated EF migration and snapshot update
- Add: focused integration tests under `Maliev.AuthService.Tests/Integration`

**Steps**

1. Add an assertion-ceremony table containing an opaque flow ID hash, challenge hash, serialized original options, service caller, application, optional principal scope, creation time, and expiry.
2. Add indexes for unique flow/challenge hashes and expiry cleanup.
3. Implement read-then-atomic-delete consumption: read the candidate options, then `ExecuteDeleteAsync` with the same ID/application/service/expiry predicates; only one concurrent caller may receive success.
4. Add `VerificationVersion`, user handle, backup state, and required verified-key storage fields to passkey credentials. Migration defaults existing rows to version `0`; authentication accepts only the new verified version.
5. Add Testcontainers integration tests for expiry, wrong application/service, sequential replay, and concurrent replay.
6. Review the generated migration for additive-only schema changes, indexes, defaults, and PostgreSQL `xmin` behavior.

## Task 4: Replace custom assertion crypto with Fido2

**Files**

- Modify: `Maliev.AuthService.Infrastructure/Maliev.AuthService.Infrastructure.csproj`
- Modify: `Maliev.AuthService.Api/Program.cs`
- Modify: `Maliev.AuthService.Application/DTOs/Request/PasskeyRequests.cs`
- Modify: `Maliev.AuthService.Application/DTOs/Response/PasskeyResponses.cs`
- Modify: `Maliev.AuthService.Application/Interfaces/IPasskeyService.cs`
- Replace authentication logic in: `Maliev.AuthService.Infrastructure/Services/PasskeyService.cs`
- Add: focused unit/component tests under `Maliev.AuthService.Tests`

**Steps**

1. Pin stable `Fido2` 4.0.1 and configure RP ID, RP name, challenge size, timeout, and an exact origin allowlist. Production configuration must fail closed when incomplete.
2. Make begin accept the server-owned application and controller-resolved service caller, generate `AssertionOptions`, persist them, and return additive `flow_id`/`expires_at_utc` fields with the existing option fields.
3. Make complete accept the opaque flow ID and Base64URL assertion bytes. Do not accept principal/email/customer claims.
4. Atomically consume the ceremony and call `IFido2.MakeAssertionAsync` with the original options, stored verified public key/counter, and a user-handle ownership callback.
5. Update sign count and backup state with optimistic concurrency. Map all verification failures to one generic authentication failure.
6. Add tests covering wrong challenge, type, origin, RP ID, UP/UV flags, signature, user handle, counter, expiry, application, caller, and replay plus a valid vector.
7. Add snake-case request/response contract tests.

## Task 5: Bind AuthService routes to the Web BFF

**Files**

- Modify: `Maliev.AuthService.Api/Controllers/AuthenticationController.cs`
- Modify: AuthService test configuration and contract tests

**Steps**

1. Generalize the existing Google exchange caller-binding pattern for passkey authentication.
2. Require `user_type=service`, the configured service name, fixed `application=web`, and `AuthPermissions.ExchangeIdentities`.
3. Ensure wrong service/application returns `403` before ceremony creation or consumption.
4. Add outcome/correlation logs without credential IDs, assertion bytes, challenge values, or customer information.

## Task 6: Add the same-origin Web BFF assertion flow

**Files**

- Add: `Maliev.Web.Bff/Security/PasskeyFlowProtector.cs`
- Modify: `Maliev.Web.Bff/Controllers/AuthController.cs`
- Modify: `Maliev.Web.Bff/Clients/CheckoutBoundaryClients.cs`
- Modify: `Maliev.Web.Bff/wwwroot/js/maliev-passkey.js`
- Extend: `Maliev.Web.Tests/PasskeySignInFlowTests.cs`
- Update all `IAuthServiceClient` fakes in tests

**Steps**

1. Add `POST /auth/passkey/begin`. It sends `{ application: "web" }` downstream, normalizes the requested return URL, and stores flow ID/return URL in a protected HttpOnly, Secure, SameSite=Strict cookie.
2. Return camel-case browser options and decode both challenge and every `allowCredentials[].id` before `navigator.credentials.get`.
3. Add `POST /auth/passkey/complete`. It requires the matching protected flow cookie, deletes it before downstream verification, and sends Base64URL assertion fields plus fixed application to AuthService.
4. On verified success only, resolve CustomerService by the returned principal, assert the canonical principal matches, map canonical customer ID/email/name/profile, and issue the shared customer cookie.
5. Map malformed flow to `400`, invalid/replayed identity to `401`, unavailable AuthService to `503`, and incomplete/mismatched downstream identity to `502`; never reveal whether a principal/credential exists.
6. Add full HTTP tests for forged legacy fields, missing/malformed flow, invalid/expired/wrong-app/replayed assertion, incomplete identity, customer mismatch, unavailable dependency, valid sign-in, cookie attributes, and return URL normalization.

## Task 7: Verification and delivery

**AuthService gates**

```powershell
dotnet test Maliev.AuthService.Tests/Maliev.AuthService.Tests.csproj --configuration Release --filter "FullyQualifiedName~Passkey"
dotnet build Maliev.AuthService.slnx --configuration Release
dotnet format Maliev.AuthService.slnx --verify-no-changes
```

**Web gates**

```powershell
dotnet test Maliev.Web.Tests/Maliev.Web.Tests.csproj --configuration Release --filter "FullyQualifiedName~PasskeySignInFlowTests"
dotnet build Maliev.Web.slnx --configuration Release
dotnet format Maliev.Web.slnx --verify-no-changes
```

**Delivery**

1. Run security review against the complete diffs and re-check browser/BFF/AuthService/CustomerService wire names.
2. Commit only the validated logical slices listed above.
3. Push the two `codex/*` branches and open linked PRs against `develop`.
4. Attach commands, SHAs, migration evidence, and residual registration risk to `maliev-ops#2`.
5. Keep issue #2 open until the verified assertion flow is merged; create/link a separate P0/P1 issue for verified registration and existing-credential re-enrolment.

## Deployment boundary

No ArgoCD application is enabled by this work. No passkey UI is exposed until secure registration and production RP/origin configuration are complete. `Maliev.Aspire` remains local/system-test orchestration only.
