# Maliev Authentication Service

JWT Token-Based Authentication Service with OAuth 2.0 Token Rotation (RFC 9700)

## Overview

Production-ready authentication microservice implementing:
- **ES256 (ECDSA P-256)** JWT token signing
- **RFC 9700** OAuth 2.0 Token Rotation with reuse detection
- **Multi-tenant** authentication (Customer/Employee)
- **SHA-256** cryptographic hashing for refresh tokens
- **Polly resilience** patterns (retry + circuit breaker)
- **Optimistic concurrency** control for token operations
- **Rate limiting** by IP address (5 attempts per 5 minutes)

## Features

- ✅ ES256 (ECDSA P-256) asymmetric JWT signing
- ✅ Automatic refresh token rotation (RFC 9700)
- ✅ Token reuse detection with family invalidation
- ✅ External service validation (Customer/Employee services)
- ✅ In-memory validation caching (5-10 minute TTL)
- ✅ PostgreSQL persistence with EF Core
- ✅ Rate limiting and circuit breaker patterns
- ✅ Correlation ID tracing (X-Correlation-Id)
- ✅ Health checks (liveness/readiness)
- ✅ Comprehensive integration test coverage

## Architecture

```
┌─────────────────┐
│   Client App    │
└────────┬────────┘
         │ POST /auth/login
         ▼
┌─────────────────────────────────────────────────────┐
│         Authentication Controller                    │
│  ┌────────────┬──────────────┬──────────────┐      │
│  │   Login    │   Refresh    │   Validate   │      │
│  └──────┬─────┴──────┬───────┴──────┬───────┘      │
└─────────┼────────────┼──────────────┼──────────────┘
          │            │              │
          ▼            ▼              ▼
┌─────────────────────────────────────────────────────┐
│         Authentication Service Layer                 │
│  ┌─────────────────────────────────────────────┐   │
│  │  Credential → External → Token → Cache      │   │
│  │  Validation   Validation  Generation         │   │
│  └─────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
          │            │              │
          ▼            ▼              ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│   External   │ │  PostgreSQL  │ │ Memory Cache │
│   Services   │ │   Database   │ │              │
└──────────────┘ └──────────────┘ └──────────────┘
```

## API Endpoints

### 1. Login (POST /auth/login)

Authenticate user and issue access + refresh tokens.

**Request:**
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "customer@example.com",
    "password": "SecurePass123!",
    "user_type": "customer"
  }'
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "a1b2c3d4e5f6...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Error Responses:**
- `400 Bad Request` - Invalid request format
- `401 Unauthorized` - Invalid credentials
- `429 Too Many Requests` - Rate limit exceeded (5 attempts per 5 minutes)
- `503 Service Unavailable` - External service or circuit breaker issue

**Rate Limiting:**
- 5 login attempts per 5 minutes per IP address
- Returns `429` when limit exceeded

---

### 2. Refresh Token (POST /auth/refresh)

Rotate refresh token and issue new access token (RFC 9700).

**Request:**
```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "a1b2c3d4e5f6..."
  }'
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "b2c3d4e5f6g7...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Error Responses:**
- `400 Bad Request` - Missing refresh_token
- `401 Unauthorized` - Invalid/expired/revoked refresh token
- `403 Forbidden` - Token reuse detected (entire family invalidated)

**Token Rotation (RFC 9700):**
1. Client sends current refresh token
2. Server validates token and checks for reuse
3. If valid: marks token as used, issues new token pair
4. If reused: invalidates entire token family (security breach)

**Reuse Detection:**
```
Time: T0          T1          T2          T3
      │           │           │           │
      Login       Refresh     Refresh     Reuse!
      Token A → Token B → Token C → Token A (INVALID)
                                      └─► Invalidate A, B, C
```

---

### 3. Validate Token (POST /auth/validate)

Validate access token and return user claims.

**Request:**
```bash
curl -X POST http://localhost:8080/auth/validate \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
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

**Error Responses:**
- `400 Bad Request` - Missing access_token
- `401 Unauthorized` - Invalid/expired/revoked token

**Caching:**
- Successful validations cached for 5-10 minutes
- Reduces external service calls by 80-90%

---

### 4. Revoke Token (POST /auth/revoke)

Revoke access token or entire token family.

**Request:**
```bash
# Revoke single access token
curl -X POST http://localhost:8080/auth/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'

# Revoke entire refresh token family
curl -X POST http://localhost:8080/auth/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "a1b2c3d4e5f6..."
  }'
```

**Response (204 No Content):**
```
(empty body)
```

**Error Responses:**
- `400 Bad Request` - Missing both access_token and refresh_token
- `404 Not Found` - Token not found

---

## Configuration

### Required Secrets (Google Secret Manager)

Mount secrets at `/mnt/secrets`:

```bash
# JWT Signing Key (ECDSA P-256 Private Key in PEM format)
/mnt/secrets/Jwt__SigningKey

# Database Connection String
/mnt/secrets/Database__ConnectionString
```

### Generate ECDSA P-256 Key Pair

```bash
# Generate private key
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem

# Extract public key
openssl ec -in private-key.pem -pubout -out public-key.pem

# Store private key in Secret Manager
gcloud secrets create jwt-signing-key \
  --data-file=private-key.pem \
  --replication-policy=automatic

# Never commit private key to source control!
```

### appsettings.json

```json
{
  "Jwt": {
    "Issuer": "https://auth.maliev.com",
    "Audience": "maliev-services",
    "SigningKey": "REPLACE_WITH_ECDSA_P256_PRIVATE_KEY_PEM",
    "AccessTokenLifetimeSeconds": 900,
    "RefreshTokenLifetimeSeconds": 2592000
  },
  "ExternalServices": {
    "CustomerServiceUrl": "http://customer-service:8080/api/v1",
    "EmployeeServiceUrl": "http://employee-service:8080/api/v1",
    "TimeoutMs": 5000,
    "MaxRetries": 3,
    "RetryDelayMs": 500
  },
  "RateLimit": {
    "LoginAttemptLimit": 5,
    "WindowSeconds": 300
  },
  "Database": {
    "ConnectionString": "Server=localhost;Port=5432;Database=auth_db;User Id=postgres;Password=postgres;"
  }
}
```

## Local Development

### Prerequisites

- .NET 9.0 SDK
- Docker Desktop (for PostgreSQL)
- Visual Studio 2022 or VS Code

### Setup

```bash
# 1. Clone repository
git clone https://github.com/MALIEV-Co-Ltd/Maliev.AuthService.git
cd Maliev.AuthService

# 2. Start PostgreSQL (Docker)
docker run -d \
  --name auth-postgres \
  -e POSTGRES_DB=auth_db \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  postgres:17

# 3. Generate development JWT key
openssl ecparam -name prime256v1 -genkey -noout -out dev-private-key.pem

# 4. Update appsettings.Development.json
cat dev-private-key.pem  # Copy content to Jwt.SigningKey

# 5. Apply database migrations
dotnet ef database update --project Maliev.AuthService.Data

# 6. Run service
dotnet run --project Maliev.AuthService.Api
```

**Service runs at:** `http://localhost:8080`

**Health Checks:**
- Liveness: `http://localhost:8080/auth/liveness`
- Readiness: `http://localhost:8080/auth/readiness`

**OpenAPI/Swagger (Development only):**
- `http://localhost:8080/openapi/v1.json`

### Testing

```bash
# Run all tests
dotnet test Maliev.AuthService.sln --verbosity normal

# Run only contract tests
dotnet test --filter "Category=Contract"

# Run only integration tests
dotnet test --filter "Category=Integration"

# Run with coverage
dotnet test /p:CollectCoverage=true /p:CoverletOutputFormat=opencover
```

**Test Categories:**
- **Contract Tests (9):** API endpoint contracts (TDD Red phase)
- **Integration Tests (28):** Complete workflows with real PostgreSQL
- **Unit Tests:** Service layer logic (post-implementation)

## Database Migrations

### Create Migration

```bash
# Port-forward to PostgreSQL pod (NOT service)
kubectl port-forward -n maliev-dev postgres-cluster-1 5432:5432

# Set connection string
export AuthDbContext="Server=localhost;Port=5432;Database=auth_db;User Id=postgres;Password=YOUR_PASSWORD;"

# Add migration
dotnet ef migrations add MigrationName --project Maliev.AuthService.Data

# Apply migration
dotnet ef database update --project Maliev.AuthService.Data
```

### Auto-Migration (Development Only)

```csharp
// Program.cs automatically applies migrations in Development environment
if (app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    var dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    await dbContext.Database.MigrateAsync();
}
```

**Production:** Use explicit migration scripts via CI/CD pipeline.

## Docker Build

```bash
# Build image
docker build -t maliev-auth-service:latest .

# Run container
docker run -d \
  --name auth-service \
  -p 8080:8080 \
  -e Database__ConnectionString="Server=host.docker.internal;Port=5432;Database=auth_db;User Id=postgres;Password=postgres;" \
  -e Jwt__SigningKey="$(cat dev-private-key.pem)" \
  maliev-auth-service:latest

# View logs
docker logs -f auth-service
```

## Kubernetes Deployment

See `DEPLOYMENT.md` for complete deployment guide.

**Quick Start:**
```bash
# Apply manifests (via GitOps)
cd maliev-gitops/3-apps/auth-service/overlays/development
kubectl apply -k .

# Check deployment
kubectl get pods -n maliev-dev | grep auth-service

# View logs
kubectl logs -f deployment/maliev-auth-service -n maliev-dev

# Port-forward for local testing
kubectl port-forward -n maliev-dev svc/maliev-auth-service 8080:8080
```

## Security Considerations

### Token Security

1. **ES256 Signing:** Asymmetric ECDSA P-256 keys prevent token forgery
2. **SHA-256 Hashing:** Refresh tokens stored as SHA-256 hashes (never plaintext)
3. **Token Rotation:** Automatic rotation on every refresh (RFC 9700)
4. **Reuse Detection:** Invalidates entire token family on reuse attempt
5. **Short-lived Access Tokens:** 15-minute expiration (configurable)
6. **Long-lived Refresh Tokens:** 30-day expiration (configurable)

### Rate Limiting

- **Login Endpoint:** 5 attempts per 5 minutes per IP
- **Partition Key:** Remote IP address (`X-Forwarded-For` aware)
- **Response:** `429 Too Many Requests` with `Retry-After` header

### Circuit Breaker

External service calls protected by Polly circuit breaker:
- **Failure Threshold:** 50% failure rate over 60 seconds
- **Break Duration:** 30 seconds (half-open state)
- **Minimum Throughput:** 10 requests before triggering

### Optimistic Concurrency

Refresh token operations use EF Core `RowVersion` for race condition prevention:
```csharp
var marked = await _repository.MarkAsUsedAsync(tokenId, currentVersion, ct);
if (!marked)
{
    // Concurrent modification detected - invalidate family
    await _repository.RevokeTokenFamilyAsync(familyId, ct);
    return null;
}
```

### Secret Management

- **Never** commit secrets to source control
- Use Google Secret Manager for production secrets
- Mount secrets at `/mnt/secrets` in Kubernetes pods
- Rotate JWT signing keys every 90 days (recommended)

## Monitoring

### Health Checks

- **Liveness:** `GET /auth/liveness` - Always returns 200 (pod alive)
- **Readiness:** `GET /auth/readiness` - Database connectivity check

```json
// Readiness response
{
  "status": "Healthy",
  "results": {
    "database": {
      "status": "Healthy",
      "description": "Database is accessible",
      "data": {}
    }
  }
}
```

### Logging

Serilog with correlation ID tracing:
```
[2025-10-06 10:30:15 INF] abc-123-def {"UserId": "12345", "Action": "Login", "UserType": "customer"}
```

**Correlation ID:**
- Request header: `X-Correlation-Id`
- Auto-generated if not provided
- Included in all log entries and error responses

### Metrics (Future)

Prometheus metrics endpoints (planned):
- `auth_login_attempts_total{status="success|failure"}`
- `auth_refresh_operations_total{status="success|reuse_detected"}`
- `auth_token_validations_total{cache_hit="true|false"}`
- `auth_external_service_calls_total{service="customer|employee",status="success|failure"}`

## Troubleshooting

### Common Issues

**1. "Invalid JWT Signature"**
- Verify `Jwt.SigningKey` is ECDSA P-256 private key in PEM format
- Check secret is mounted correctly at `/mnt/secrets/Jwt__SigningKey`
- Ensure key matches public key distributed to downstream services

**2. "Database Connection Failed"**
- Verify PostgreSQL is running: `kubectl get pods -n maliev-dev | grep postgres`
- Check connection string: `kubectl get secret maliev-auth-secrets -n maliev-dev -o yaml`
- Port-forward to pod (not service): `kubectl port-forward postgres-cluster-1 5432:5432`

**3. "External Service Validation Timeout"**
- Check Customer/Employee service health: `kubectl get pods -n maliev-dev`
- Verify service URLs in configuration
- Check circuit breaker logs for failures

**4. "Rate Limit Exceeded (429)"**
- Default: 5 login attempts per 5 minutes per IP
- Clear rate limit: restart service or wait 5 minutes
- Adjust `RateLimit.LoginAttemptLimit` and `RateLimit.WindowSeconds`

**5. "Token Reuse Detected (403)"**
- Client attempted to reuse old refresh token
- Entire token family invalidated (security measure)
- User must re-authenticate with /auth/login

## License

Copyright © 2025 MALIEV Co. Ltd. All rights reserved.

## Support

- **Issues:** https://github.com/MALIEV-Co-Ltd/Maliev.AuthService/issues
- **Documentation:** See `DEPLOYMENT.md` and inline code comments
- **Contact:** dev@maliev.com
