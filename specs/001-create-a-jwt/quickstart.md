# QuickStart Guide: JWT Authentication Service

**Feature**: 001-create-a-jwt
**Purpose**: End-to-end validation of authentication service functionality
**Prerequisites**: Docker, .NET 10.0 SDK, PostgreSQL client

**Last Updated**: 2025-11-29 (Synchronized with .NET 10.0 implementation)

---

## Environment Setup

### 1. Start Test PostgreSQL Database

```powershell
# Navigate to repository root
cd Maliev.AuthService

# Start PostgreSQL container (or use existing)
docker run --name auth-postgres -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres:15-alpine

# Wait for startup (5-10 seconds)
Start-Sleep -Seconds 10

# Verify PostgreSQL is running
docker exec auth-postgres pg_isready -U postgres
```

### 2. Configure Environment Variables

```powershell
# Set database connection string
$env:ConnectionStrings__AuthDbContext="Host=localhost;Port=5432;Database=auth_test_db;Username=postgres;Password=postgres;"

# Set JWT configuration (Base64-encoded PEM keys for development - NOT for production)
# These are test keys from appsettings.Testing.json
$env:Jwt__PrivateKey="<base64-encoded-rsa-private-key-pem>"
$env:Jwt__PublicKey="<base64-encoded-rsa-public-key-pem>"
$env:Jwt__Issuer="https://dev.api.maliev.com/auth"
$env:Jwt__Audience="https://dev.api.maliev.com"

# Set external service URLs (will use circuit breaker if unavailable)
$env:ExternalServices__CustomerService__BaseUrl="http://localhost:5001"
$env:ExternalServices__EmployeeService__BaseUrl="http://localhost:5002"

# Set CORS allowed origins
$env:CORS__AllowedOrigins="http://localhost:3000,https://dev.intranet.maliev.com"

# Optional: Redis and RabbitMQ (will gracefully degrade if not available)
# $env:ConnectionStrings__redis="localhost:6379"
# $env:ConnectionStrings__rabbitmq="amqp://guest:guest@localhost:5672"
```

### 3. Apply Database Migrations

```powershell
# Navigate to solution root
cd Maliev.AuthService

# Apply migrations
dotnet ef database update --project Maliev.AuthService.Data --startup-project Maliev.AuthService.Api

# Verify tables created
docker exec -it auth-postgres psql -U postgres -d auth_test_db -c "\dt"
```

**Expected Tables**:
- `refresh_tokens`
- `token_families`
- `revoked_tokens`
- `account_lockouts`
- `ip_rate_limits`
- `auth_audit_logs`
- `service_credentials`

### 4. Start the Application

```powershell
# Run the API
dotnet run --project Maliev.AuthService.Api

# Application starts on:
# https://localhost:7xxx (HTTPS)
# http://localhost:5xxx (HTTP)

# Scalar API documentation available at:
# https://localhost:7xxx/auth/scalar
```

---

## Scenario 1: Customer Login Flow

### Test Objective
Validate customer authentication with token generation and refresh token rotation.

### Steps

**1.1. Customer Login**

```bash
curl -X POST https://localhost:7xxx/auth/v1/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "customer@example.com",
    "password": "<password>",
    "user_type": "customer"
  }'
```

**Expected Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "a1b2c3d4e5f6...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Note**: Response uses snake_case (e.g., `access_token`, not `accessToken`)

**Validation Checks**:
- ✅ Response contains `access_token` and `refresh_token`
- ✅ `access_token` is valid JWT with RS256 (RSA-2048) signature
- ✅ Database contains new `refresh_token` record with SHA-256 hash
- ✅ Database contains new `token_family` record
- ✅ `auth_audit_log` contains successful login event

**1.2. Validate Access Token**

```bash
ACCESS_TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

curl -X POST https://localhost:7xxx/auth/v1/validate \
  -H "Content-Type: application/json" \
  -d "{
    \"access_token\": \"$ACCESS_TOKEN\"
  }"
```

**Expected Response** (200 OK):
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "user_type": "customer",
  "username": "john.doe",
  "email": "customer@example.com",
  "roles": ["Customer"],
  "permissions": []
}
```

**1.3. Refresh Access Token**

```bash
REFRESH_TOKEN="a1b2c3d4e5f6..."

curl -X POST https://localhost:7xxx/auth/v1/refresh \
  -H "Content-Type: application/json" \
  -d "{
    \"refresh_token\": \"$REFRESH_TOKEN\"
  }"
```

**Expected Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...[NEW]",
  "refresh_token": "x9y8z7w6v5...[NEW-DIFFERENT]",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Validation Checks**:
- ✅ New `access_token` differs from original
- ✅ New `refresh_token` differs from original
- ✅ Old refresh token marked as `is_used = TRUE` in database
- ✅ New refresh token has same `family_id`

**1.4. Detect Refresh Token Reuse (OAuth 2.0 RFC 9700)**

```bash
# Attempt to reuse OLD refresh token
curl -X POST https://localhost:7xxx/auth/v1/refresh \
  -H "Content-Type: application/json" \
  -d "{
    \"refresh_token\": \"$REFRESH_TOKEN\"
  }"
```

**Expected Response** (401 Unauthorized):
```json
{
  "error": "invalid_token",
  "error_description": "Invalid or expired refresh token"
}
```

**Validation Checks**:
- ✅ Response status is 401
- ✅ All tokens in token family invalidated
- ✅ Audit log contains reuse detection event
- ✅ User must re-authenticate

---

## Scenario 2: Service-to-Service Authentication

### Test Objective
Validate service authentication with client credentials.

### Steps

**2.1. Service Login**

```bash
curl -X POST https://localhost:7xxx/auth/v1/service/login \
  -H "Content-Type: application/json" \
  -d '{
    "service_name": "customer-service",
    "service_secret": "<client-secret>"
  }'
```

**Expected Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Validation Checks**:
- ✅ Service access token issued
- ✅ Token contains service-specific claims (no user context)
- ✅ Audit log contains service authentication event

---

## Scenario 3: Rate Limiting and Account Lockout

### Test Objective
Validate multi-layer rate limiting (account-based, IP-based, progressive delays).

### Steps

**3.1. Test Account Lockout (5 Failed Attempts)**

```powershell
# PowerShell loop for Windows
1..5 | ForEach-Object {
  curl -X POST https://localhost:7xxx/auth/v1/login `
    -H "Content-Type: application/json" `
    -d '{
      "email": "customer@example.com",
      "password": "wrong-password",
      "user_type": "customer"
    }'
  Write-Host "`nAttempt $_ completed"
  Start-Sleep -Seconds 1
}
```

**Expected Responses**:
- Attempts 1-2: 401 Unauthorized (immediate)
- Attempt 3: 401 Unauthorized (1 second delay before response)
- Attempt 4: 401 Unauthorized (2 second delay before response)
- Attempt 5: 423 Locked

**Response for Attempt 5** (423 Locked):
```json
{
  "error": "account_locked",
  "error_description": "Account locked due to failed login attempts",
  "locked_until": "2025-11-29T12:00:00Z"
}
```

**Validation Checks**:
- ✅ Progressive delays observed (0s → 1s → 2s → 4s)
- ✅ 5th attempt returns 423 Locked
- ✅ `locked_until` is 15 minutes from lockout
- ✅ Database `account_lockouts` has record with `failed_attempts = 5`

---

## Scenario 4: Health Checks

### Test Objective
Validate liveness and readiness probes for Kubernetes orchestration.

### Steps

**4.1. Liveness Check**

```bash
curl https://localhost:7xxx/auth/liveness
```

**Expected Response** (200 OK):
```
"Healthy"
```

**4.2. Readiness Check**

```bash
curl https://localhost:7xxx/auth/readiness
```

**Expected Response** (200 OK):
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

**4.3. Metrics (Prometheus)**

```bash
curl https://localhost:7xxx/metrics
```

**Expected**: OpenMetrics format output with HTTP and auth metrics

---

## Scenario 5: API Documentation (Scalar)

### Test Objective
Validate interactive API documentation.

### Steps

**5.1. Access Scalar UI**

```
Open browser: https://localhost:7xxx/auth/scalar
```

**Validation Checks**:
- ✅ Scalar UI loads successfully
- ✅ All endpoints documented
- ✅ Request/response schemas visible
- ✅ Can test endpoints interactively

**5.2. OpenAPI JSON**

```bash
curl https://localhost:7xxx/auth/openapi/v1.json
```

**Expected**: Valid OpenAPI 3.0 specification JSON

---

## Cleanup

```powershell
# Stop application (Ctrl+C)

# Stop and remove test database
docker stop auth-postgres
docker rm auth-postgres

# Clear environment variables
Remove-Item Env:ConnectionStrings__AuthDbContext
Remove-Item Env:Jwt__*
Remove-Item Env:ExternalServices__*
Remove-Item Env:CORS__*
```

---

## Success Criteria

✅ **All scenarios completed successfully**:
- ✅ Scenario 1: Customer login, token validation, refresh, reuse detection
- ✅ Scenario 2: Service-to-service authentication
- ✅ Scenario 3: Rate limiting (account + IP), progressive delays, lockouts
- ✅ Scenario 4: Health checks (liveness + readiness + metrics)
- ✅ Scenario 5: API documentation (Scalar + OpenAPI)

✅ **Security validations passed**:
- ✅ RSA-2048 (RS256) JWT signature verification
- ✅ Refresh token rotation working (OAuth 2.0 RFC 9700)
- ✅ Token reuse detection invalidates token family
- ✅ SHA-256 hash storage for refresh tokens
- ✅ Multi-layer rate limiting prevents brute force

✅ **Technology stack validated**:
- ✅ .NET 10.0 runtime
- ✅ Entity Framework Core 10.0
- ✅ PostgreSQL 15+
- ✅ Scalar interactive documentation
- ✅ Prometheus metrics
- ✅ MassTransit infrastructure (configured, ready for events)
- ✅ Redis caching (graceful degradation if unavailable)

✅ **API conventions confirmed**:
- ✅ All endpoints under `/auth` prefix
- ✅ snake_case JSON properties
- ✅ Correlation ID propagation
- ✅ Centralized exception handling

**Status**: Feature 001-create-a-jwt is **PRODUCTION-READY** on .NET 10.0! 🎉
