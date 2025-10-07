# QuickStart Guide: JWT Authentication Service

**Feature**: 001-create-a-jwt
**Purpose**: End-to-end validation of authentication service functionality
**Prerequisites**: Docker, .NET 9 SDK, PostgreSQL client

---

## Environment Setup

### 1. Start Test PostgreSQL Database

```powershell
# Navigate to repository root
cd R:\maliev\Maliev.AuthService

# Start PostgreSQL container
docker-compose -f docker-compose.test.yml up -d

# Wait for health check (10-15 seconds)
docker-compose -f docker-compose.test.yml ps

# Verify PostgreSQL is running
docker exec authservice-test-db pg_isready -U postgres
```

### 2. Configure Environment Variables

```powershell
# Set database connection string
$env:ConnectionStrings__AuthServiceDbContext="Host=localhost;Port=5432;Database=test_db;Username=postgres;Password=postgres;"

# Set JWT configuration (development keys - NOT for production)
$env:Jwt__SecurityKey="<dev-jwt-key-min-32-chars-for-hs256-algorithm>"
$env:Jwt__Issuer="maliev-dev"
$env:Jwt__Audience="maliev-dev"

# Set external service URLs (mock endpoints for testing)
$env:ExternalServices__CustomerService__BaseUrl="http://localhost:5001"
$env:ExternalServices__EmployeeService__BaseUrl="http://localhost:5002"

# Set CORS allowed origins
$env:CORS_ALLOWED_ORIGINS="https://dev.intranet.maliev.com,https://dev.www.maliev.com"
```

### 3. Apply Database Migrations

```powershell
# Navigate to solution root
cd R:\maliev\Maliev.AuthService

# Apply migrations
dotnet ef database update --project Maliev.AuthService.Data --startup-project Maliev.AuthService.Api

# Verify tables created
docker exec -it authservice-test-db psql -U postgres -d test_db -c "\dt"
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

# Application should start on:
# https://localhost:7xxx and http://localhost:5xxx
# Swagger UI auto-opens at /auth/swagger
```

---

## Scenario 1: Customer Login Flow

### Test Objective
Validate customer authentication with external customer service validation, token generation, and refresh token rotation.

### Prerequisites
- Mock customer service running on http://localhost:5001
- Valid customer credentials: `customer@example.com` / `<password>`

### Steps

**1.1. Customer Login**

```bash
curl -X POST https://localhost:7xxx/auth/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "customer@example.com",
    "password": "<password>",
    "user_type": "customer"
  }'
```

**Expected Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "CfDJ8KZx...rT0gg",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "user_id": "123e4567-e89b-12d3-a456-426614174000",
    "user_type": "customer",
    "username": "john.doe",
    "email": "customer@example.com",
    "roles": ["Customer"],
    "permissions": []
  }
}
```

**Validation Checks**:
- ✅ Response contains `access_token` and `refresh_token`
- ✅ `access_token` is valid JWT with EdDSA signature
- ✅ `user.user_type` equals `"customer"`
- ✅ Database contains new `refresh_token` record with hashed token
- ✅ Database contains new `token_family` record
- ✅ `auth_audit_log` contains successful login event

**1.2. Validate Access Token**

```bash
# Extract access_token from previous response
ACCESS_TOKEN="eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9..."

curl -X POST https://localhost:7xxx/auth/v1/auth/validate \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": "'"$ACCESS_TOKEN"'"
  }'
```

**Expected Response** (200 OK):
```json
{
  "valid": true,
  "user": {
    "user_id": "123e4567-e89b-12d3-a456-426614174000",
    "user_type": "customer",
    "username": "john.doe",
    "email": "customer@example.com",
    "roles": ["Customer"],
    "permissions": []
  }
}
```

**Validation Checks**:
- ✅ `valid` equals `true`
- ✅ User identity matches login response

**1.3. Refresh Access Token**

```bash
# Extract refresh_token from login response
REFRESH_TOKEN="CfDJ8KZx...rT0gg"

curl -X POST https://localhost:7xxx/auth/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "'"$REFRESH_TOKEN"'"
  }'
```

**Expected Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...[NEW]",
  "refresh_token": "CfDJ8KZx...[NEW-DIFFERENT]",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Validation Checks**:
- ✅ New `access_token` is different from original
- ✅ New `refresh_token` is different from original
- ✅ Database shows old refresh token marked as `is_used = TRUE`
- ✅ Database contains new refresh token with same `family_id`
- ✅ Old refresh token cannot be reused (next step)

**1.4. Detect Refresh Token Reuse**

```bash
# Attempt to reuse OLD refresh token
curl -X POST https://localhost:7xxx/auth/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "'"$REFRESH_TOKEN"'"
  }'
```

**Expected Response** (403 Forbidden):
```json
{
  "error": "token_reuse_detected",
  "message": "Refresh token reuse detected. All tokens have been invalidated for security.",
  "action_required": "re_authenticate"
}
```

**Validation Checks**:
- ✅ Response status is 403 Forbidden
- ✅ Error indicates token reuse detection
- ✅ Database shows ALL tokens in family marked as invalid
- ✅ `auth_audit_log` contains reuse detection event
- ✅ User must re-authenticate (login again)

---

## Scenario 2: Employee Login and Token Revocation

### Test Objective
Validate employee authentication, token validation, and distributed token revocation.

### Prerequisites
- Mock employee service running on http://localhost:5002
- Valid employee credentials: `employee@example.com` / `<password>`

### Steps

**2.1. Employee Login**

```bash
curl -X POST https://localhost:7xxx/auth/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "employee@example.com",
    "password": "<password>",
    "user_type": "employee"
  }'
```

**Expected Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "CfDJ8KZx...rT0gg",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "user_id": "456e7890-e89b-12d3-a456-426614174000",
    "user_type": "employee",
    "username": "jane.smith",
    "email": "employee@example.com",
    "roles": ["Employee", "Manager"],
    "permissions": []
  }
}
```

**Validation Checks**:
- ✅ `user.user_type` equals `"employee"`
- ✅ `user.roles` contains employee-specific roles

**2.2. Use Access Token for Authorization**

```bash
# Use access token in Authorization header
ACCESS_TOKEN="eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9..."

curl -X POST https://localhost:7xxx/auth/v1/auth/revoke \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jti": "550e8400-e29b-41d4-a716-446655440000",
    "reason": "admin_action"
  }'
```

**Expected Response** (204 No Content)

**Validation Checks**:
- ✅ Response status is 204 (no content)
- ✅ Database contains revoked token record
- ✅ Redis pub/sub event published to `token:revoked` channel
- ✅ Revocation propagates to all services in <2 seconds

**2.3. Validate Revoked Token (Fails)**

```bash
# Token with jti "550e8400-e29b-41d4-a716-446655440000"
REVOKED_TOKEN="eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...[REVOKED]"

curl -X POST https://localhost:7xxx/auth/v1/auth/validate \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": "'"$REVOKED_TOKEN"'"
  }'
```

**Expected Response** (401 Unauthorized):
```json
{
  "error": "invalid_token",
  "message": "Token validation failed",
  "validation_failure": "revoked"
}
```

**Validation Checks**:
- ✅ Response status is 401 Unauthorized
- ✅ `validation_failure` equals `"revoked"`
- ✅ Token found in revocation cache OR database

**2.4. Logout (Revoke All Tokens)**

```bash
curl -X POST https://localhost:7xxx/auth/v1/auth/logout \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

**Expected Response** (204 No Content)

**Validation Checks**:
- ✅ Response status is 204
- ✅ All refresh tokens for user marked as revoked
- ✅ All active access tokens for user added to revocation list
- ✅ `auth_audit_log` contains logout event

---

## Scenario 3: Rate Limiting and Account Lockout

### Test Objective
Validate multi-layer rate limiting (account-based, IP-based, progressive delays).

### Steps

**3.1. Test Account Lockout (5 Failed Attempts)**

```bash
# Attempt 1-5 with invalid password
for i in {1..5}; do
  curl -X POST https://localhost:7xxx/auth/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{
      "username": "customer@example.com",
      "password": "wrong-password",
      "user_type": "customer"
    }'
  echo "\nAttempt $i completed"
  sleep 1
done
```

**Expected Responses**:
- Attempts 1-2: 401 Unauthorized (invalid credentials)
- Attempt 3: 401 Unauthorized with 1 second delay
- Attempt 4: 401 Unauthorized with 2 second delay
- Attempt 5: 423 Locked

**Response for Attempt 5** (423 Locked):
```json
{
  "error": "account_locked",
  "message": "Account locked due to failed login attempts",
  "locked_until": "2025-10-06T15:30:00Z",
  "retry_after": 900
}
```

**Validation Checks**:
- ✅ Progressive delays observed (1s → 2s → 4s)
- ✅ 5th attempt returns 423 Locked
- ✅ `locked_until` is 15 minutes from lockout
- ✅ Database `account_lockouts` table has record with `failed_attempts = 5`

**3.2. Test IP-Based Rate Limiting (20 Failed Attempts Across Accounts)**

```bash
# Attempt 20 failed logins from same IP with different usernames
for i in {1..20}; do
  curl -X POST https://localhost:7xxx/auth/v1/auth/login \
    -H "Content-Type: application/json" \
    -d "{
      \"username\": \"user$i@example.com\",
      \"password\": \"wrong\",
      \"user_type\": \"customer\"
    }"
  sleep 0.5
done
```

**Expected Response for Attempt 20** (429 Too Many Requests):
```json
{
  "error": "rate_limit_exceeded",
  "message": "Too many requests, please retry after indicated time",
  "retry_after": 900,
  "limit": 20,
  "remaining": 0
}
```

**Validation Checks**:
- ✅ 20th attempt returns 429 Too Many Requests
- ✅ Database `ip_rate_limits` table has blocked IP
- ✅ `blocked_until` is 15 minutes from block
- ✅ All subsequent requests from IP return 429 until block expires

---

## Scenario 4: Service-to-Service Authentication

### Test Objective
Validate service authentication with client credentials.

### Prerequisites
- Service credential created in database: `client_id = "service-dev-customer-api"`, `client_secret = "<secret>"`

### Steps

**4.1. Service Login**

```bash
curl -X POST https://localhost:7xxx/auth/v1/auth/service/login \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "service-dev-customer-api",
    "client_secret": "<client-secret>"
  }'
```

**Expected Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "service": {
    "client_id": "service-dev-customer-api",
    "service_name": "Customer Service"
  }
}
```

**Validation Checks**:
- ✅ Service access token issued
- ✅ Token contains service-specific claims (no user context)
- ✅ `auth_audit_log` contains service authentication event

**4.2. Validate Service Token**

```bash
SERVICE_TOKEN="eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9..."

curl -X POST https://localhost:7xxx/auth/v1/auth/validate \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": "'"$SERVICE_TOKEN"'"
  }'
```

**Expected Response** (200 OK):
```json
{
  "valid": true,
  "user": {
    "user_id": "service-dev-customer-api",
    "user_type": "service",
    "username": "Customer Service",
    "email": null,
    "roles": ["Service"],
    "permissions": []
  }
}
```

**Validation Checks**:
- ✅ `user_type` equals `"service"`
- ✅ No user email or personal data

---

## Scenario 5: Circuit Breaker and Resilience

### Test Objective
Validate circuit breaker behavior when external services are unavailable.

### Steps

**5.1. Stop External Customer Service**

```bash
# Simulate external service failure
docker stop customer-service-mock
```

**5.2. Attempt Customer Login (Circuit Breaker Opens)**

```bash
# Attempt 5 logins to trigger circuit breaker
for i in {1..5}; do
  curl -X POST https://localhost:7xxx/auth/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{
      "username": "customer@example.com",
      "password": "<password>",
      "user_type": "customer"
    }'
  echo "\nAttempt $i"
done
```

**Expected Responses**:
- Attempts 1-5: 503 Service Unavailable (timeout/connection refused)
- Attempts 6+: 503 Service Unavailable (circuit breaker open - immediate failure)

**Response** (503):
```json
{
  "error": "service_unavailable",
  "message": "External validation service unavailable. Circuit breaker is open."
}
```

**Validation Checks**:
- ✅ Circuit opens after 5 consecutive failures
- ✅ Subsequent requests fail immediately (no timeout wait)
- ✅ Health check reflects circuit state: `customer_service_circuit: Open`

**5.3. Validate Existing Tokens Still Work**

```bash
# Use previously issued access token
curl -X POST https://localhost:7xxx/auth/v1/auth/validate \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": "'"$EXISTING_TOKEN"'"
  }'
```

**Expected Response** (200 OK):
```json
{
  "valid": true,
  "user": { ... }
}
```

**Validation Checks**:
- ✅ Token validation works even when external service is down
- ✅ Validation only requires public signing key (no external dependency)

**5.4. Circuit Breaker Recovery**

```bash
# Restart external service
docker start customer-service-mock

# Wait 30 seconds for circuit to enter half-open state
sleep 30

# Attempt login (test request)
curl -X POST https://localhost:7xxx/auth/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "customer@example.com",
    "password": "<password>",
    "user_type": "customer"
  }'
```

**Expected Response** (200 OK):
```json
{
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": { ... }
}
```

**Validation Checks**:
- ✅ Circuit enters half-open state after 30 seconds
- ✅ Test request succeeds → Circuit closes
- ✅ Health check shows: `customer_service_circuit: Closed`
- ✅ Normal operations resume

---

## Scenario 6: Health Checks

### Test Objective
Validate liveness and readiness probes for Kubernetes orchestration.

### Steps

**6.1. Liveness Check**

```bash
curl https://localhost:7xxx/auth/liveness
```

**Expected Response** (200 OK):
```
Healthy
```

**6.2. Readiness Check**

```bash
curl https://localhost:7xxx/auth/readiness
```

**Expected Response** (200 OK):
```json
{
  "status": "Healthy",
  "checks": {
    "database": {
      "status": "Healthy",
      "description": "PostgreSQL connection successful"
    },
    "customer_service_circuit": {
      "status": "Healthy",
      "description": "Circuit closed"
    },
    "employee_service_circuit": {
      "status": "Healthy",
      "description": "Circuit closed"
    }
  }
}
```

**Validation Checks**:
- ✅ Overall `status` is `"Healthy"`
- ✅ Database check passes
- ✅ Circuit breaker states reported
- ✅ Response time < 100ms

---

## Cleanup

```powershell
# Stop application (Ctrl+C)

# Stop and remove test database
docker-compose -f docker-compose.test.yml down -v

# Clear environment variables
Remove-Item Env:ConnectionStrings__AuthServiceDbContext
Remove-Item Env:Jwt__*
Remove-Item Env:ExternalServices__*
Remove-Item Env:CORS_ALLOWED_ORIGINS
```

---

## Success Criteria

✅ **All 6 scenarios completed successfully**
- ✅ Scenario 1: Customer login, token validation, refresh, reuse detection
- ✅ Scenario 2: Employee login, token revocation, logout
- ✅ Scenario 3: Rate limiting (account + IP), progressive delays, lockouts
- ✅ Scenario 4: Service-to-service authentication
- ✅ Scenario 5: Circuit breaker (open, half-open, closed states)
- ✅ Scenario 6: Health checks (liveness + readiness)

✅ **Security validations passed**:
- ✅ EdDSA (Ed25519) JWT signature verification
- ✅ Refresh token rotation working
- ✅ Token reuse detection invalidates token family
- ✅ Distributed token revocation propagates in <2s
- ✅ SHA-256 hash storage for refresh tokens and service secrets
- ✅ Multi-layer rate limiting prevents brute force

✅ **Performance validated**:
- ✅ Authentication: <200ms p95
- ✅ Token validation: <50ms p95
- ✅ Circuit breaker: 30s recovery time

✅ **Observability confirmed**:
- ✅ Structured logs (JSON) to stdout
- ✅ Audit trail in `auth_audit_logs` table
- ✅ Correlation ID propagation
- ✅ Health checks reflect system state

**Status**: Feature 001-create-a-jwt is production-ready! 🎉
