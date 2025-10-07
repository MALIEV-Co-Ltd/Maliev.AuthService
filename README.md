# Maliev Authentication Service

Production-ready JWT token-based authentication service with OAuth 2.0 token rotation compliance (RFC 9700).

## Features

- **RSA-2048 Asymmetric Signing**: Secure JWT signing with public/private key cryptography
- **OAuth 2.0 RFC 9700 Compliance**: Automatic refresh token rotation with reuse detection
- **Dual User Types**: Separate authentication flows for customers and employees
- **Multi-Layer Security**:
  - Account lockout (5 failures / 15 minutes)
  - IP rate limiting (20 requests / 15 minutes)
  - Progressive delay on failed attempts
- **Service-to-Service Authentication**: Dedicated auth flow for microservices
- **Complete Token Lifecycle**: Generation, validation, refresh, revocation with audit logging
- **Production-Ready**: Structured logging, health checks, correlation IDs, error handling

## Quick Start

### Prerequisites

- .NET 9.0 SDK
- PostgreSQL 15+
- Docker (optional, for local PostgreSQL)

### Local Development

1. **Clone repository**
   ```bash
   git clone https://github.com/MALIEV-Co-Ltd/Maliev.AuthService.git
   cd Maliev.AuthService
   ```

2. **Set up PostgreSQL**
   ```bash
   # Using Docker
   docker run --name auth-postgres -e POSTGRES_PASSWORD=dummy -p 5432:5432 -d postgres:15
   ```

3. **Set connection string**
   ```powershell
   # Windows PowerShell
   $env:RefreshTokenDbContext="Server=localhost;Port=5432;Database=auth_app_db;User Id=postgres;Password=dummy;"

   # Linux/macOS
   export RefreshTokenDbContext="Server=localhost;Port=5432;Database=auth_app_db;User Id=postgres;Password=dummy;"
   ```

4. **Run database migrations**
   ```bash
   dotnet ef database update --project Maliev.AuthService.Data
   ```

5. **Run the service**
   ```bash
   dotnet run --project Maliev.AuthService.Api
   ```

6. **Access Swagger UI**
   ```
   http://localhost:5000/auth/swagger
   ```

## API Endpoints

All endpoints are prefixed with `/auth` base path.

### Authentication

#### Login (Customer/Employee)
```http
POST /auth/v1/login
Content-Type: application/json

{
  "username": "customer@example.com",
  "password": "SecurePassword123!",
  "user_type": "customer"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "a1b2c3d4e5f6g7h8i9j0...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Error Codes:**
- `400` - Invalid request (validation failure)
- `401` - Invalid credentials
- `423` - Account locked (too many failed attempts)
- `429` - Rate limit exceeded
- `503` - External service unavailable

---

#### Service Login
```http
POST /auth/v1/service/login
Content-Type: application/json

{
  "service_name": "customer-service",
  "service_secret": "secret-key-here"
}
```

**Response:** Same format as customer/employee login

---

#### Refresh Token
```http
POST /auth/v1/refresh
Content-Type: application/json

{
  "refresh_token": "a1b2c3d4e5f6g7h8i9j0..."
}
```

**Response:** New access token and refresh token (old refresh token invalidated)

**Token Rotation:** Each refresh generates a new token pair. Old refresh tokens are marked as used. If an old token is reused, the entire token family is invalidated for security.

**Error Codes:**
- `400` - Missing refresh token
- `401` - Invalid/expired token
- `403` - Token reuse detected (family invalidated)

---

#### Validate Token
```http
POST /auth/v1/validate
Content-Type: application/json

{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200 OK):**
```json
{
  "user_id": "12345",
  "user_type": "customer",
  "username": "customer@example.com",
  "email": "customer@example.com",
  "roles": ["customer"],
  "permissions": ["read:profile", "write:orders"]
}
```

**Caching:** Successful validations are cached for 5-10 minutes to improve performance.

---

#### Revoke Token
```http
POST /auth/v1/revoke
Content-Type: application/json

{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200 OK):**
```json
{
  "message": "Token revoked successfully"
}
```

Revoked tokens are stored in the database and checked during validation.

---

#### Logout
```http
POST /auth/v1/logout
Content-Type: application/json

{
  "refresh_token": "a1b2c3d4e5f6g7h8i9j0..."
}
```

**Response (200 OK):**
```json
{
  "message": "Logged out successfully"
}
```

Invalidates the entire token family associated with the refresh token.

---

### Health Checks

#### Liveness Probe
```http
GET /auth/liveness
```

**Response (200 OK):** `"Healthy"`

---

#### Readiness Probe
```http
GET /auth/readiness
```

**Response (200 OK):**
```json
{
  "status": "Healthy",
  "results": {
    "AuthDbContext": {
      "status": "Healthy",
      "description": "Database is accessible"
    }
  }
}
```

## Configuration

### Required Secrets (Google Secret Manager)

Production secrets are stored in Google Secret Manager:

```
Jwt:PrivateKey  - Base64-encoded RSA-2048 private key (PEM format)
Jwt:PublicKey   - Base64-encoded RSA-2048 public key (PEM format)
ConnectionStrings:RefreshTokenDbContext - PostgreSQL connection string
```

### Environment Variables

```bash
# Database
RefreshTokenDbContext="Server=localhost;Port=5432;Database=auth_app_db;User Id=postgres;Password=..."

# JWT Configuration
Jwt:Issuer="https://dev.api.maliev.com/auth"
Jwt:Audience="https://dev.api.maliev.com"
Jwt:AccessTokenLifetimeMinutes=15
Jwt:RefreshTokenLifetimeDays=7

# External Services
ExternalServices:CustomerService:BaseUrl="http://customer-service:8080"
ExternalServices:EmployeeService:BaseUrl="http://employee-service:8080"

# Rate Limiting
RateLimit:MaxAttempts=20
RateLimit:WindowMinutes=15

# Account Lockout
AccountLockout:MaxFailedAttempts=5
AccountLockout:LockoutDurationMinutes=15
```

### Generating RSA Keys

For production use, generate RSA-2048 key pairs:

```bash
# Generate private key
openssl genrsa -out private_key.pem 2048

# Extract public key
openssl rsa -in private_key.pem -pubout -out public_key.pem

# Base64 encode for Google Secret Manager
cat private_key.pem | base64 -w 0 > private_key_base64.txt
cat public_key.pem | base64 -w 0 > public_key_base64.txt
```

**Note:** Test keys are provided in `appsettings.Testing.json` for local development only.

## Database Schema

The service uses PostgreSQL with 7 entities:

1. **RefreshToken** - Stores hashed refresh tokens with expiration
2. **TokenFamily** - Tracks token rotation lineage for reuse detection
3. **RevokedAccessToken** - Stores revoked access token JTIs
4. **AccountLockout** - Tracks failed login attempts per account
5. **IpRateLimit** - Tracks API requests per IP address
6. **AuthAuditLog** - Comprehensive audit trail of all auth operations
7. **ServiceCredential** - Service-to-service authentication credentials

### Database Migration

```bash
# Port forward to PostgreSQL (Kubernetes)
kubectl port-forward -n maliev-dev postgres-cluster-1 5432:5432

# Set connection string
export RefreshTokenDbContext="Server=localhost;Port=5432;Database=auth_app_db;User Id=postgres;Password=..."

# Apply migrations
dotnet ef database update --project Maliev.AuthService.Data
```

Current migration: `InitialCreate` (20251007014518)

## Testing

The service includes comprehensive test coverage with 27 tests (100% pass rate).

### Running Tests

```bash
# Run all tests
dotnet test Maliev.AuthService.sln --verbosity normal

# Run with coverage
dotnet test --collect:"XPlat Code Coverage"

# Run specific test suite
dotnet test --filter "FullyQualifiedName~AuthenticationContractTests"
```

### Test Suites

- **Authentication Contract Tests** (6 tests) - Login validation, error handling, lockout
- **Service Login Contract Tests** (4 tests) - Service authentication validation
- **Token Refresh Contract Tests** (5 tests) - Token rotation, expiry, reuse detection
- **Token Validation Contract Tests** (5 tests) - Validation, revocation, expiry
- **Token Revocation Contract Tests** (3 tests) - Revocation, idempotency
- **Logout Contract Tests** (3 tests) - Token family revocation
- **Health Check Contract Tests** (2 tests) - Liveness and readiness probes

## Deployment

### Kubernetes

The service is deployed via GitOps using ArgoCD. Manifests are located in the `maliev-gitops` repository.

**Namespace:** `maliev-dev` (development), `maliev-staging` (staging), `maliev-prod` (production)

**Service URL:** `http://maliev-auth-service:8080/auth`

### CI/CD

GitHub Actions workflows handle automated deployment:

- **develop** branch → Development environment
- **staging** branch → Staging environment
- **main** branch → Production environment

Each workflow:
1. Builds and tests the service
2. Creates Docker image
3. Pushes to Google Artifact Registry
4. Updates GitOps repository with new image tag
5. ArgoCD automatically syncs and deploys

### Monitoring

- **Logs:** Structured JSON logs via Serilog (console output)
- **Health Checks:** `/auth/liveness` and `/auth/readiness` endpoints
- **Correlation IDs:** All requests tagged with `X-Correlation-ID` header

## Security Considerations

### Token Security

- **Access Tokens:** Short-lived (15 minutes), signed with RSA-2048
- **Refresh Tokens:** Long-lived (7 days), stored as SHA-256 hashes
- **Token Rotation:** New refresh token on each use (RFC 9700)
- **Reuse Detection:** Entire token family invalidated on reuse attempt
- **Revocation:** JTI-based access token revocation with database storage

### Rate Limiting

- **Account-based:** 5 failed login attempts in 15 minutes → Account lockout
- **IP-based:** 20 requests per 15 minutes per IP → Rate limit error
- **Progressive Delays:** Exponential backoff on failed login attempts

### Best Practices

- **Never** store private keys in source code or environment variables
- **Always** use Google Secret Manager for production secrets
- **Rotate** RSA keys periodically (recommended: every 90 days)
- **Monitor** audit logs for suspicious activity
- **Validate** all user inputs with FluentValidation
- **Use HTTPS** in production (enforced by middleware)

## Troubleshooting

### Issue: Tests fail with database connection errors
**Solution:** Tests use in-memory database. Ensure `ASPNETCORE_ENVIRONMENT=Testing` is set.

### Issue: Token validation always fails
**Solution:** Verify public key matches the private key used for signing. Check Google Secret Manager configuration.

### Issue: Rate limit errors in development
**Solution:** Increase rate limits in `appsettings.Development.json` or clear `IpRateLimit` table.

### Issue: SwaggerUI returns 404
**Solution:** Swagger is disabled in production. Set `ASPNETCORE_ENVIRONMENT=Development` or `Staging`.

### Issue: Database migration fails
**Solution:** Ensure PostgreSQL is running and `RefreshTokenDbContext` environment variable is set correctly.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Client Application                      │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           │ HTTPS
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              Maliev.AuthService.Api (ASP.NET Core)          │
├─────────────────────────────────────────────────────────────┤
│  Controllers                                                 │
│  ├─ AuthenticationController                                │
│  Middleware                                                  │
│  ├─ CorrelationIdMiddleware                                 │
│  ├─ ExceptionHandlingMiddleware                             │
│  Services                                                    │
│  ├─ AuthenticationService                                   │
│  ├─ TokenGenerator (RSA-2048)                               │
│  ├─ TokenValidator                                          │
│  ├─ RefreshTokenService (RFC 9700)                          │
│  ├─ AccountLockoutService                                   │
│  └─ RateLimitService                                        │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│         Maliev.AuthService.Data (Entity Framework)          │
├─────────────────────────────────────────────────────────────┤
│  DbContext: AuthDbContext                                    │
│  Repositories                                                │
│  ├─ RefreshTokenRepository                                  │
│  ├─ TokenFamilyRepository                                   │
│  └─ RevokedAccessTokenRepository                            │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │  PostgreSQL  │
                    │  auth_app_db │
                    └──────────────┘
```

## Contributing

1. Create feature branch from `develop`
2. Implement feature with tests
3. Ensure all tests pass (`dotnet test`)
4. Create pull request to `develop`
5. After review, merge to `develop` for deployment

## License

Copyright © 2025 Maliev Co. Ltd. All rights reserved.
