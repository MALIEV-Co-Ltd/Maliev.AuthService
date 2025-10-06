# Quickstart Manual Testing Guide

**Project**: Maliev.AuthService
**Feature**: 001-create-a-jwt
**Date**: 2025-10-05
**Purpose**: Manual testing scenarios for JWT authentication service validation

---

## Prerequisites

### 1. Service Running Locally

```bash
# Terminal 1: Start the authentication service
cd R:\maliev\Maliev.AuthService
dotnet run --project Maliev.AuthService.Api

# Service should be listening on http://localhost:8080
```

### 2. Database Running

```bash
# Terminal 2: Start PostgreSQL (or use existing dev database)
docker run -d \
  --name auth-postgres \
  -e POSTGRES_PASSWORD=test123 \
  -e POSTGRES_DB=auth_db \
  -p 5432:5432 \
  postgres:18

# Apply migrations
export AuthDbContext="Server=localhost;Port=5432;Database=auth_db;User Id=postgres;Password=test123;"
dotnet ef database update --project Maliev.AuthService.Data
```

### 3. External Validation Services (Mock)

For local testing, the service should have development fallbacks or mock external services configured.

```json
// appsettings.Development.json
{
  "ExternalServices": {
    "CustomerValidationUrl": "http://localhost:9001",
    "EmployeeValidationUrl": "http://localhost:9002"
  }
}
```

### 4. Tools

- **curl** (command line HTTP client)
- **jq** (JSON processor - optional but recommended)
- **HTTPie** (alternative to curl - optional)

---

## Test Scenarios

### Scenario 1: Customer Login Flow ✅

**Objective**: Test complete customer authentication flow from login to token validation

#### Step 1.1: Customer Login (Success)

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "customer@example.com",
    "password": "test123",
    "user_type": "customer"
  }' | jq '.'
```

**Expected Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "RToyMzQ1Njc4OTBhYmNkZWY=",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Headers to Check**:
- `X-Correlation-ID`: Should be present
- `X-RateLimit-Limit`: 5
- `X-RateLimit-Remaining`: 4 (decrements on each attempt)
- `X-RateLimit-Reset`: Unix timestamp

**Save tokens for next steps**:
```bash
export ACCESS_TOKEN="<access_token_from_response>"
export REFRESH_TOKEN="<refresh_token_from_response>"
```

#### Step 1.2: Validate Access Token

```bash
curl -X POST http://localhost:8080/auth/validate \
  -H "Content-Type: application/json" \
  -d "{
    \"access_token\": \"$ACCESS_TOKEN\"
  }" | jq '.'
```

**Expected Response** (200 OK):
```json
{
  "user_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "user_type": "customer",
  "username": "customer@example.com",
  "email": "customer@example.com",
  "roles": ["customer"],
  "permissions": ["view_orders", "create_order", "view_profile"]
}
```

**Verify**:
- ✅ `user_type` is "customer"
- ✅ `user_id` matches the authenticated user
- ✅ `roles` and `permissions` are populated

#### Step 1.3: Refresh Token (Token Rotation)

```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{
    \"refresh_token\": \"$REFRESH_TOKEN\"
  }" | jq '.'
```

**Expected Response** (200 OK):
```json
{
  "access_token": "NEW_ACCESS_TOKEN_HERE",
  "refresh_token": "NEW_REFRESH_TOKEN_HERE",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Verify**:
- ✅ New access_token is different from original
- ✅ New refresh_token is different from original
- ✅ Old refresh_token is marked as "used" in database

**Update tokens**:
```bash
export ACCESS_TOKEN_NEW="<new_access_token>"
export REFRESH_TOKEN_NEW="<new_refresh_token>"
```

#### Step 1.4: Try to Reuse Old Refresh Token (Reuse Detection)

```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{
    \"refresh_token\": \"$REFRESH_TOKEN\"
  }" | jq '.'
```

**Expected Response** (401 Unauthorized):
```json
{
  "error": "token_family_invalidated",
  "error_description": "Token reuse detected. All tokens in this session have been invalidated. Please re-authenticate.",
  "correlation_id": "abc123..."
}
```

**Verify**:
- ✅ Error is `token_family_invalidated`
- ✅ All tokens in the token family are revoked in database
- ✅ Even the NEW refresh token no longer works

**Database Check**:
```sql
SELECT id, is_used, is_revoked, revoked_at
FROM refresh_tokens
WHERE family_id = (
  SELECT family_id FROM refresh_tokens
  WHERE token_hash = SHA256('<old_refresh_token>')
);

-- Expected: All tokens have is_revoked = true
```

**Result**: ✅ Token reuse detection working correctly

---

### Scenario 2: Employee Login Flow ✅

**Objective**: Verify employee authentication uses different validation endpoint

#### Step 2.1: Employee Login

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "employee@maliev.com",
    "password": "employee123",
    "user_type": "employee"
  }' | jq '.'
```

**Expected Response** (200 OK):
```json
{
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

#### Step 2.2: Validate Employee Token

```bash
export EMPLOYEE_ACCESS_TOKEN="<access_token_from_response>"

curl -X POST http://localhost:8080/auth/validate \
  -H "Content-Type: application/json" \
  -d "{
    \"access_token\": \"$EMPLOYEE_ACCESS_TOKEN\"
  }" | jq '.'
```

**Expected Response** (200 OK):
```json
{
  "user_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
  "user_type": "employee",
  "username": "employee@maliev.com",
  "email": "employee@maliev.com",
  "roles": ["employee", "admin"],
  "permissions": ["manage_orders", "manage_users", "view_analytics"]
}
```

**Verify**:
- ✅ `user_type` is "employee"
- ✅ Different permissions than customer

**Result**: ✅ Employee authentication working correctly

---

### Scenario 3: Rate Limiting (Account-Based) ⚠️

**Objective**: Verify account lockout after 5 failed attempts

#### Step 3.1: Make 5 Failed Login Attempts

```bash
# Attempt 1
curl -i -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "customer@example.com",
    "password": "WRONG_PASSWORD",
    "user_type": "customer"
  }'
# Expected: 401 Unauthorized, X-RateLimit-Remaining: 4

# Attempt 2
curl -i -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "customer@example.com",
    "password": "WRONG_PASSWORD",
    "user_type": "customer"
  }'
# Expected: 401 Unauthorized, X-RateLimit-Remaining: 3

# Attempt 3 (Progressive delay: 1 second)
curl -i -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "customer@example.com",
    "password": "WRONG_PASSWORD",
    "user_type": "customer"
  }'
# Expected: 401 Unauthorized, X-RateLimit-Remaining: 2, ~1s delay

# Attempt 4 (Progressive delay: 2 seconds)
curl -i -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "customer@example.com",
    "password": "WRONG_PASSWORD",
    "user_type": "customer"
  }'
# Expected: 401 Unauthorized, X-RateLimit-Remaining: 1, ~2s delay

# Attempt 5 (Progressive delay: 4 seconds)
curl -i -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "customer@example.com",
    "password": "WRONG_PASSWORD",
    "user_type": "customer"
  }'
# Expected: 429 Too Many Requests, X-RateLimit-Remaining: 0, ~4s delay
```

**Expected Response on 5th Attempt** (429 Too Many Requests):
```json
{
  "error": "too_many_requests",
  "error_description": "Too many failed login attempts. Account locked for 15 minutes.",
  "retry_after": 900,
  "correlation_id": "..."
}
```

**Headers**:
- `Retry-After`: 900 (15 minutes in seconds)
- `X-RateLimit-Limit`: 5
- `X-RateLimit-Remaining`: 0
- `X-RateLimit-Reset`: Unix timestamp (current time + 900 seconds)

#### Step 3.2: Verify Lockout Persists

```bash
# Immediate retry should also fail
curl -i -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "customer@example.com",
    "password": "test123",
    "user_type": "customer"
  }'
# Expected: 429 Too Many Requests (even with CORRECT password)
```

#### Step 3.3: Wait 15 Minutes (Optional)

```bash
# Wait 15 minutes or adjust system time for testing
sleep 900

# Retry with correct password
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "customer@example.com",
    "password": "test123",
    "user_type": "customer"
  }' | jq '.'

# Expected: 200 OK (account unlocked)
```

**Result**: ✅ Account-based rate limiting working correctly

---

### Scenario 4: Rate Limiting (IP-Based) ⚠️

**Objective**: Verify IP blocking after 20 attempts across different accounts

#### Step 4.1: Make 20 Failed Attempts Across Different Accounts

```bash
for i in {1..20}; do
  echo "Attempt $i from IP"
  curl -i -X POST http://localhost:8080/auth/login \
    -H "Content-Type: application/json" \
    -d "{
      \"username\": \"user$i@example.com\",
      \"password\": \"WRONG\",
      \"user_type\": \"customer\"
    }"
  sleep 0.5
done

# Expected: 20th attempt returns 429 with IP-based rate limit error
```

**Expected Response on 20th Attempt** (429 Too Many Requests):
```json
{
  "error": "too_many_requests",
  "error_description": "Too many requests from this IP address. Please try again later.",
  "retry_after": 900,
  "correlation_id": "..."
}
```

**Verify**:
- ✅ IP address is blocked even for different usernames
- ✅ Retry-After header is present

**Result**: ✅ IP-based rate limiting working correctly

---

### Scenario 5: Access Token Revocation 🔒

**Objective**: Test distributed token revocation

#### Step 5.1: Login and Get Access Token

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "customer@example.com",
    "password": "test123",
    "user_type": "customer"
  }' | jq '.'

export REVOKE_ACCESS_TOKEN="<access_token>"
```

#### Step 5.2: Validate Token (Before Revocation)

```bash
curl -X POST http://localhost:8080/auth/validate \
  -H "Content-Type: application/json" \
  -d "{
    \"access_token\": \"$REVOKE_ACCESS_TOKEN\"
  }" | jq '.'

# Expected: 200 OK (token is valid)
```

#### Step 5.3: Revoke Access Token

```bash
curl -i -X POST http://localhost:8080/auth/revoke \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $REVOKE_ACCESS_TOKEN" \
  -d "{
    \"access_token\": \"$REVOKE_ACCESS_TOKEN\",
    \"reason\": \"user_logout\"
  }"

# Expected: 204 No Content
```

#### Step 5.4: Validate Token (After Revocation)

```bash
curl -X POST http://localhost:8080/auth/validate \
  -H "Content-Type: application/json" \
  -d "{
    \"access_token\": \"$REVOKE_ACCESS_TOKEN\"
  }" | jq '.'
```

**Expected Response** (401 Unauthorized):
```json
{
  "error": "token_revoked",
  "error_description": "The access token has been revoked",
  "correlation_id": "..."
}
```

**Database Check**:
```sql
SELECT jti, revoked_at, reason
FROM revoked_access_tokens
WHERE jti = '<jti_from_token>';

-- Expected: Entry exists with reason = 'user_logout'
```

**Result**: ✅ Access token revocation working correctly

---

### Scenario 6: Circuit Breaker (External Service Failure) 🔌

**Objective**: Test circuit breaker behavior when external validation service is down

#### Step 6.1: Stop External Validation Service

```bash
# Stop mock customer validation service (or simulate network failure)
# Method depends on your setup
```

#### Step 6.2: Make 5 Login Attempts

```bash
for i in {1..5}; do
  echo "Attempt $i"
  curl -i -X POST http://localhost:8080/auth/login \
    -H "Content-Type: application/json" \
    -d '{
      "username": "customer@example.com",
      "password": "test123",
      "user_type": "customer"
    }'
  sleep 1
done
```

**Expected Behavior**:
- Attempts 1-4: May timeout or return errors (circuit breaker tracking failures)
- Attempt 5: Circuit breaker opens

**Expected Response After Circuit Opens** (503 Service Unavailable):
```json
{
  "error": "service_unavailable",
  "error_description": "Authentication service is temporarily unavailable. Please try again later.",
  "correlation_id": "..."
}
```

#### Step 6.3: Check Health Endpoint

```bash
curl http://localhost:8080/auth/readiness | jq '.'
```

**Expected Response** (503 Service Unavailable):
```json
{
  "status": "Degraded",
  "checks": [
    {
      "name": "PostgreSQL",
      "status": "Healthy"
    },
    {
      "name": "CustomerValidationService",
      "status": "Unhealthy",
      "description": "Circuit breaker open"
    }
  ]
}
```

#### Step 6.4: Restart External Service and Wait 30 Seconds

```bash
# Restart mock service
# Wait 30 seconds (circuit breaker duration)
sleep 30

# Retry login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "customer@example.com",
    "password": "test123",
    "user_type": "customer"
  }' | jq '.'

# Expected: 200 OK (circuit breaker closed)
```

**Result**: ✅ Circuit breaker working correctly

---

### Scenario 7: Token Expiration ⏰

**Objective**: Verify access token expiration handling

#### Step 7.1: Login and Extract Token

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "customer@example.com",
    "password": "test123",
    "user_type": "customer"
  }' | jq '.'

export EXPIRY_ACCESS_TOKEN="<access_token>"
```

#### Step 7.2: Decode Token to Check Expiration

```bash
# Decode JWT (using jwt.io or command line)
echo $EXPIRY_ACCESS_TOKEN | cut -d'.' -f2 | base64 -d | jq '.'

# Check 'exp' claim (should be current_time + 900 seconds)
```

#### Step 7.3: Wait 16 Minutes (or Adjust System Time)

```bash
# Option 1: Wait 16 minutes
sleep 960

# Option 2: Adjust system time for testing (requires elevated permissions)
# Not recommended for production testing
```

#### Step 7.4: Validate Expired Token

```bash
curl -X POST http://localhost:8080/auth/validate \
  -H "Content-Type: application/json" \
  -d "{
    \"access_token\": \"$EXPIRY_ACCESS_TOKEN\"
  }" | jq '.'
```

**Expected Response** (401 Unauthorized):
```json
{
  "error": "token_expired",
  "error_description": "The access token has expired",
  "correlation_id": "..."
}
```

**Result**: ✅ Token expiration working correctly

---

### Scenario 8: Distributed Tracing (Correlation ID) 🔍

**Objective**: Verify correlation ID propagation

#### Step 8.1: Send Request with Custom Correlation ID

```bash
curl -i -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Correlation-ID: my-custom-trace-123" \
  -d '{
    "username": "customer@example.com",
    "password": "test123",
    "user_type": "customer"
  }'
```

**Expected**:
- Response header includes `X-Correlation-ID: my-custom-trace-123`
- Logs show correlation ID in all log entries for this request

#### Step 8.2: Send Request Without Correlation ID

```bash
curl -i -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "customer@example.com",
    "password": "test123",
    "user_type": "customer"
  }'
```

**Expected**:
- Response header includes `X-Correlation-ID: <auto-generated-uuid>`
- Service generates correlation ID automatically

**Log Check**:
```bash
# Check logs for correlation ID
tail -f /var/log/maliev-auth-service.log | grep "my-custom-trace-123"
```

**Result**: ✅ Correlation ID propagation working correctly

---

## Health Checks

### Liveness Probe

```bash
curl http://localhost:8080/auth/liveness

# Expected: 200 OK
# Response: "Healthy"
```

### Readiness Probe

```bash
curl http://localhost:8080/auth/readiness | jq '.'

# Expected: 200 OK (if all dependencies healthy)
# Response:
{
  "status": "Healthy",
  "checks": [
    {
      "name": "PostgreSQL",
      "status": "Healthy",
      "description": "Database connection successful"
    },
    {
      "name": "CustomerValidationService",
      "status": "Healthy",
      "description": "Circuit breaker closed"
    },
    {
      "name": "EmployeeValidationService",
      "status": "Healthy",
      "description": "Circuit breaker closed"
    }
  ]
}
```

---

## Database Verification Queries

### Check Token Families

```sql
SELECT family_id, user_id, user_type, created_at, last_used_at
FROM token_families
ORDER BY created_at DESC
LIMIT 10;
```

### Check Refresh Tokens

```sql
SELECT id, user_id, user_type, is_used, is_revoked, created_at, expires_at
FROM refresh_tokens
ORDER BY created_at DESC
LIMIT 20;
```

### Check Revoked Access Tokens

```sql
SELECT jti, revoked_at, expires_at, reason
FROM revoked_access_tokens
ORDER BY revoked_at DESC;
```

### Count Active vs Revoked Tokens

```sql
SELECT
  is_revoked,
  is_used,
  COUNT(*) as count
FROM refresh_tokens
GROUP BY is_revoked, is_used;
```

---

## Performance Testing

### Basic Load Test (Optional)

```bash
# Using Apache Bench (ab)
ab -n 1000 -c 10 -p login-payload.json -T application/json \
  http://localhost:8080/auth/login

# Expected:
# - Requests per second: >100
# - p95 latency: <200ms
```

```json
// login-payload.json
{
  "username": "customer@example.com",
  "password": "test123",
  "user_type": "customer"
}
```

---

## Cleanup

### Reset Database

```bash
# Drop and recreate database
psql -U postgres -c "DROP DATABASE auth_db;"
psql -U postgres -c "CREATE DATABASE auth_db;"

# Reapply migrations
dotnet ef database update --project Maliev.AuthService.Data
```

### Clear Rate Limit Cache

```bash
# Restart service to clear in-memory rate limit state
# Or wait 15 minutes for automatic reset
```

---

## Troubleshooting

### Issue: External Validation Service Not Responding

**Symptom**: All login attempts return 503
**Solution**: Check `appsettings.Development.json` for correct service URLs

### Issue: Database Connection Failed

**Symptom**: Readiness probe returns unhealthy
**Solution**: Verify PostgreSQL is running and connection string is correct

### Issue: Token Rotation Not Working

**Symptom**: Old refresh token still works after rotation
**Solution**: Check database to verify `is_used` flag is set

### Issue: Rate Limiting Not Applied

**Symptom**: Can make >5 failed attempts without lockout
**Solution**: Verify rate limiting middleware is registered in Program.cs

---

## Next Steps

After manual testing:
1. ✅ All scenarios pass → Proceed to automated integration tests
2. ⚠️ Any scenario fails → Fix issues and re-test
3. 📝 Document any edge cases discovered during testing

---

**Document Status**: Complete ✅
**Test Coverage**: 8 primary scenarios
**Next Artifact**: Automated integration tests implementation
