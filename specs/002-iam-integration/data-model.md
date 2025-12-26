# Data Model: AuthService IAM Integration

## Entities

### Principal (Logical)
The authenticated identity for which permissions and roles are being resolved.
- `PrincipalId`: UUID (Primary identifier for IAM resolution)
- `PrincipalType`: Enum (User, Service)
- `Email`: String (Optional, for token claims)
- `Name`: String (Optional, for token claims)

### PermissionResolutionRequest (API)
- `PrincipalId`: UUID (Required)
- `IncludeResourceScoped`: Boolean (Default: false)

### PermissionResolutionResponse (API)
- `PrincipalId`: UUID
- `Permissions`: List<String> (e.g., ["invoice.read", "invoice.create"])
- `Roles`: List<String> (e.g., ["admin", "accountant"])
- `ResolvedAt`: DateTime (UTC)
- `CacheUntil`: DateTime? (Optional, hint from IAM)

## Identity & Uniqueness
- Principals are uniquely identified by their `PrincipalId`.
- In migration mode, `UserId` is used as the `PrincipalId`.

## State Transitions
1. **Authentication**: Credentials validated by upstream provider.
2. **Resolution**: AuthService calls IAM to fetch permissions for the resolved `PrincipalId`.
3. **Issuance**: JWT generated with embedded permissions and roles.
