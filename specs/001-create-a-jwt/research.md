# Research: JWT Token-Based Authentication Service

**Feature**: 001-create-a-jwt
**Date**: 2025-10-06
**Status**: Complete

## Overview
This document consolidates research findings for implementing a production-ready JWT authentication microservice with OAuth 2.0 RFC 9700 compliance, refresh token rotation, distributed token revocation, and comprehensive security features.

---

## 1. JWT Signing Algorithm Selection

### Decision: RSA-2048 (RS256)

### Rationale:
- **Compatibility**: RS256 is the most widely supported algorithm across all JWT libraries and platforms
- **Performance**: Hardware acceleration for RSA is ubiquitous, performance difference is negligible for this use case
- **Security**: 2048-bit RSA provides sufficient security margin for current standards (NIST recommendations)
- **Standard Compliance**: RS256 is the mandatory "must implement" algorithm in JWT RFCs

### Alternatives Considered:
- **EdDSA (Ed25519)**: Rejected - While faster, library support is less universal than RSA
- **ECDSA (ES256)**: Rejected - Potential nonce reuse vulnerabilities if RNG is weak
- **HS256 (HMAC)**: Rejected - Symmetric algorithm unsuitable for distributed token validation (requires shared secret)

### Implementation:
```csharp
// .NET 10.0 Implementation
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

var rsa = RSA.Create();
rsa.ImportFromPem(privateKeyPem); // Load from PEM
var signingKey = new RsaSecurityKey(rsa);
var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256);
```

---

## 2. Refresh Token Storage Pattern

### Decision: SHA-256 Hash Storage with Constant-Time Comparison

### Rationale:
- **Security**: Storing hashes instead of plaintext tokens prevents database breach exploitation
- **OAuth 2.0 RFC 9700**: Explicitly recommends hashing refresh tokens in storage
- **Constant-Time Comparison**: Prevents timing attacks when validating tokens
- **Performance**: SHA-256 is fast and widely supported in .NET cryptographic libraries

### Alternatives Considered:
- **Plaintext Storage**: Rejected - High security risk if database is compromised
- **Encryption**: Rejected - Adds complexity, key management overhead, and doesn't prevent privileged user misuse
- **bcrypt/Argon2**: Rejected - Overkill for token storage (designed for password hashing with intentional slowness)

### Implementation Pattern:
```csharp
// Token Generation
var refreshToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
var tokenHash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(refreshToken)));

// Storage
await _context.RefreshTokens.AddAsync(new RefreshToken
{
    TokenHash = tokenHash, // Store hash only
    UserId = userId,
    ExpiresAt = DateTime.UtcNow.AddDays(7)
});

// Validation (constant-time comparison)
var providedHash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(providedToken)));
var storedHash = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.Id == tokenId);

if (!CryptographicOperations.FixedTimeEquals(
    Encoding.UTF8.GetBytes(providedHash),
    Encoding.UTF8.GetBytes(storedHash.TokenHash)))
{
    throw new UnauthorizedAccessException("Invalid refresh token");
}
```

---

## 3. Distributed Token Revocation Architecture

### Decision: Redis Pub/Sub with Database Fallback

### Rationale:
- **Fast Propagation**: Redis pub/sub delivers revocation events to all services in <2 seconds
- **Eventual Consistency**: Acceptable trade-off for security (2s window vs immediate consistency complexity)
- **Fallback Mechanism**: Database query ensures revocation enforcement even if Redis is unavailable
- **Scalability**: Pub/sub pattern scales horizontally without N² message complexity

### Alternatives Considered:
- **Immediate Database Queries**: Rejected - High latency for every token validation
- **Kafka/Event Streaming**: Rejected - Overkill for this use case, adds operational complexity
- **In-Memory Cache Only**: Rejected - No persistence, lost on service restart

### Architecture:
```
1. User logs out → AuthService publishes revocation event to Redis channel "token:revoked"
2. All services subscribe to "token:revoked" channel
3. On receiving event → Add token JTI to local in-memory revocation cache (15min TTL)
4. Token validation checks:
   a. Check local cache first (fast path)
   b. If not in cache → Check database revocation table (fallback)
   c. If revoked → Reject token and add to local cache
```

### Implementation Notes:
- Use StackExchange.Redis for .NET integration
- Configure Redis with persistence (AOF or RDB) for revocation durability
- Set TTL on local cache entries equal to access token expiration (15 minutes)
- Database fallback query: `SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti = @jti AND expires_at > NOW())`

---

## 4. Circuit Breaker Pattern for External Services

### Decision: Polly Circuit Breaker with Half-Open State Testing

### Rationale:
- **Resilience**: Prevents cascading failures when external customer/employee services are down
- **Fast Failure**: Immediately returns 503 when circuit is open, avoiding timeout waits
- **Automatic Recovery**: Half-open state tests service health before fully closing circuit
- **Industry Standard**: Polly is the de facto library for .NET resilience patterns

### Configuration:
- **Failure Threshold**: 5 consecutive failures → Circuit opens
- **Break Duration**: 30 seconds before attempting recovery
- **Half-Open Test**: 1 request to test if service is healthy
- **Success Threshold**: 1 successful test request → Circuit closes

### Alternatives Considered:
- **Retry Without Circuit Breaker**: Rejected - Causes timeout accumulation and resource exhaustion
- **Manual Circuit State Management**: Rejected - Complex to implement correctly, error-prone
- **Immediate Rejection (No Recovery)**: Rejected - Services should auto-recover when external dependency is restored

### Implementation:
```csharp
var circuitBreakerPolicy = Policy
    .Handle<HttpRequestException>()
    .CircuitBreakerAsync(
        handledEventsAllowedBeforeBreaking: 5,
        durationOfBreak: TimeSpan.FromSeconds(30),
        onBreak: (exception, duration) =>
        {
            _logger.LogWarning("Circuit breaker opened for {Duration}s", duration.TotalSeconds);
        },
        onReset: () =>
        {
            _logger.LogInformation("Circuit breaker reset");
        },
        onHalfOpen: () =>
        {
            _logger.LogInformation("Circuit breaker half-open, testing...");
        }
    );
```

---

## 5. Rate Limiting Strategy

### Decision: Multi-Layer Rate Limiting

### Rationale:
- **Defense in Depth**: Multiple layers provide comprehensive protection
- **Granular Control**: Different limits for different threat models
- **ASP.NET Core 10.0 Native**: Built-in rate limiting avoids external dependencies

### Layers:
1. **Account-Based Rate Limiting**: 5 failed attempts → 15min lockout (prevents brute force per account)
2. **IP-Based Rate Limiting**: 20 failed attempts → 15min IP block (prevents distributed brute force)
3. **Progressive Delays**: 1s (3 attempts) → 2s (4 attempts) → 4s (5 attempts) before processing request
4. **Endpoint-Specific Limits**:
   - General endpoints: 100 req/min per IP (fixed window)
   - Batch operations: 10 req/min per IP (sliding window with 6 segments)
   - Service-to-service: 1000 validations/min, 100 generations/min per service

### Alternatives Considered:
- **Single Layer (Account Only)**: Rejected - Vulnerable to distributed attacks across many accounts
- **CAPTCHA**: Rejected - Not suitable for API-first microservice architecture
- **Third-Party Rate Limiter**: Rejected - ASP.NET Core 10.0 built-in provides sufficient functionality

### Implementation:
```csharp
builder.Services.AddRateLimiter(options =>
{
    // General endpoints
    options.AddFixedWindowLimiter("general", opt =>
    {
        opt.PermitLimit = 100;
        opt.Window = TimeSpan.FromMinutes(1);
        opt.QueueLimit = 10;
    });

    // Batch operations
    options.AddSlidingWindowLimiter("batch", opt =>
    {
        opt.PermitLimit = 10;
        opt.Window = TimeSpan.FromMinutes(1);
        opt.SegmentsPerWindow = 6;
    });

    options.OnRejected = async (context, token) =>
    {
        context.HttpContext.Response.StatusCode = 429;
        await context.HttpContext.Response.WriteAsJsonAsync(new
        {
            error = "Too many requests",
            retryAfter = context.Lease.RetryAfter?.TotalSeconds
        }, token);
    };
});
```

---

## 6. Token Family Tracking for Reuse Detection

### Decision: Family ID-Based Lineage Tracking

### Rationale:
- **OAuth 2.0 RFC 9700 Compliance**: Implements refresh token rotation with reuse detection
- **Security**: Detects token theft and invalidates entire compromised lineage
- **Simplicity**: Family ID approach avoids complex parent-child relationship tracking

### How It Works:
1. **Login**: Generate new family_id (GUID), store with first refresh token
2. **Token Refresh**: Issue new refresh token with SAME family_id, invalidate old token
3. **Reuse Detection**: If already-used token is presented → Find all tokens with same family_id → Invalidate entire family
4. **Cleanup**: Expired families are deleted after grace period (30 days)

### Alternatives Considered:
- **Parent-Child Token Tracking**: Rejected - Complex queries, circular reference risks
- **No Family Tracking**: Rejected - Cannot detect token reuse across multiple refresh cycles
- **Device-Based Tracking**: Deferred to v1.1 - Adds complexity for device fingerprinting

### Database Schema:
```sql
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    family_id UUID NOT NULL,
    user_id UUID NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    INDEX idx_family_id (family_id),
    INDEX idx_user_id (user_id),
    INDEX idx_token_hash (token_hash)
);
```

---

## 7. External Service Integration Patterns

### Decision: Typed HttpClient with Polly Retry Policies

### Rationale:
- **Type Safety**: Typed HttpClient pattern provides strongly-typed service clients
- **Dependency Injection**: Integrates seamlessly with ASP.NET Core DI container
- **Resilience**: Polly retry policies handle transient failures automatically
- **Configuration**: External service URLs loaded from Google Secret Manager

### Retry Configuration:
- **Max Attempts**: 3
- **Backoff**: Exponential (100ms → 200ms → 400ms)
- **Total Timeout**: 5 seconds
- **Retryable Errors**: Network failures, 5xx responses, timeouts

### Implementation:
```csharp
// Service options configuration
public class ExternalServiceOptions
{
    public required string BaseUrl { get; set; }
    public int TimeoutSeconds { get; set; } = 180;
}

// HttpClient registration
var retryPolicy = HttpPolicyExtensions
    .HandleTransientHttpError()
    .WaitAndRetryAsync(3, retryAttempt => TimeSpan.FromMilliseconds(Math.Pow(2, retryAttempt) * 100));

builder.Services.AddHttpClient<ICustomerServiceClient, CustomerServiceClient>((serviceProvider, client) =>
{
    var config = serviceProvider.GetRequiredService<IConfiguration>();
    var options = config.GetSection("ExternalServices:CustomerService").Get<ExternalServiceOptions>()
        ?? throw new InvalidOperationException("ExternalServices:CustomerService configuration not found");

    client.BaseAddress = new Uri(options.BaseUrl);
    client.Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds);
})
.AddPolicyHandler(retryPolicy);
```

---

## 8. Testing Strategy with Actual PostgreSQL

### Decision: Real PostgreSQL Database for All Tests

### Rationale:
- **Behavioral Accuracy**: In-memory databases don't replicate PostgreSQL-specific behaviors (e.g., RowVersion, triggers, constraints)
- **Migration Validation**: Tests run actual migrations, catching schema issues early
- **Concurrency Testing**: Real database enables testing of optimistic concurrency control
- **Production Parity**: Test environment mirrors production database behavior

### Test Infrastructure:
1. **docker-compose.test.yml**: Local PostgreSQL 15+ container for development testing
2. **GitHub Actions Service Container**: PostgreSQL 15+ with health checks in CI/CD
3. **TestDatabaseFixture**: Shared fixture applies migrations and seeds reference data
4. **Cleanup Pattern**: Delete test data between tests, reuse schema for performance

### Alternatives Considered:
- **In-Memory Database (SQLite)**: Rejected - Doesn't support PostgreSQL-specific features
- **Shared Test Database**: Rejected - Test isolation issues, parallel execution conflicts
- **Database-per-Test**: Rejected - Too slow, migration overhead for each test

### Configuration:
```yaml
# docker-compose.test.yml
services:
  postgres-test:
    image: postgres:15-alpine
    container_name: authservice-test-db
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: test_db
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5
```

---

## 9. Secrets Management Architecture

### Decision: Google Secret Manager with Environment Variable Injection

### Rationale:
- **Zero Secrets in Code**: All sensitive values external to repository
- **Environment-Specific Configuration**: Different secrets per environment (dev/staging/prod)
- **Kubernetes Integration**: Secrets mounted as files at /mnt/secrets, loaded as environment variables
- **Audit Trail**: Google Secret Manager tracks all secret access and modifications

### Secret Naming Convention:
- Database: `ConnectionStrings__AuthServiceDbContext`
- JWT: `Jwt__SecurityKey`, `Jwt__Issuer`, `Jwt__Audience`
- External Services: `ExternalServices__CustomerService__BaseUrl`
- CORS: `CORS_ALLOWED_ORIGINS` (comma-separated)

### Loading Pattern:
```csharp
// Program.cs
var secretsPath = "/mnt/secrets";
if (Directory.Exists(secretsPath))
{
    builder.Configuration.AddKeyPerFile(directoryPath: secretsPath, optional: true);
}

// Double underscore converts to colon in IConfiguration
// ConnectionStrings__AuthServiceDbContext → ConnectionStrings:AuthServiceDbContext
var connectionString = builder.Configuration.GetConnectionString("AuthServiceDbContext")
    ?? throw new InvalidOperationException("Database connection string not configured");
```

### Security Compliance:
- ✅ No production endpoints in source code
- ✅ No database credentials in repository
- ✅ Documentation uses placeholder values only
- ✅ Test configurations use localhost or mock URLs

---

## 10. Middleware Pipeline Order

### Decision: Strict Order Enforcement

### Rationale:
- **Exception Handling First**: Catches all exceptions from downstream middleware
- **Logging Second**: Logs all requests including those that cause exceptions
- **Security Last**: Authentication/Authorization after infrastructure middleware

### Mandatory Order:
1. ExceptionHandlingMiddleware (catches all exceptions)
2. RequestLoggingMiddleware (logs all requests)
3. Swagger/SwaggerUI (API documentation)
4. HTTPS Redirection
5. CORS
6. Rate Limiter
7. Authentication
8. Authorization
9. Health Checks
10. Controllers

### Rationale for Order:
- Exception handling MUST be first to catch errors from all other middleware
- Logging MUST be early to capture request context before processing
- CORS MUST be before authentication to handle preflight requests
- Rate limiter MUST be before authentication to prevent auth resource exhaustion
- Authentication MUST be before authorization (obvious dependency)

---

## 11. Performance Optimization Strategies

### Decision: Multi-Level Caching with Invalidation

### Rationale:
- **Reduce Database Load**: Cache frequently accessed data
- **Fast Token Validation**: In-memory revocation cache for <10ms validation
- **External Service Caching**: Cache customer/employee validation responses (TTL: 5 minutes)

### Caching Strategy:
1. **Token Revocation Cache**: In-memory, TTL = access token expiration (15 minutes)
2. **User Identity Cache**: In-memory, TTL = 5 minutes, invalidated on user updates
3. **Circuit Breaker State**: In-memory, managed by Polly
4. **NO Database Query Caching**: EF Core connection pooling provides sufficient performance

### Critical Implementation:
```csharp
// NEVER use MemoryCache with SizeLimit unless Size property is set on ALL entries
builder.Services.AddMemoryCache(); // Simple configuration without SizeLimit
```

---

## 12. Observability and Monitoring

### Decision: Structured Logging with Prometheus Metrics

### Rationale:
- **Structured Logs**: JSON format to stdout enables log aggregation (Loki/ELK)
- **Prometheus Metrics**: Industry standard for Kubernetes monitoring
- **Distributed Tracing**: Correlation ID propagation for request tracing across services
- **Health Checks**: Liveness and readiness probes for Kubernetes orchestration

### Metrics Exposed:
- Authentication success/failure rates by user type
- Token generation/refresh/validation latency (histogram)
- External service availability (circuit breaker state)
- Rate limit violations
- Revocation event propagation time

### Logging Configuration:
```csharp
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .WriteTo.Console(new JsonFormatter()) // JSON to stdout only
    .Enrich.WithCorrelationId()
    .Enrich.WithMachineName()
    .CreateLogger();
```

---

## Research Completion Summary

✅ **All Technical Decisions Made** - No NEEDS CLARIFICATION remaining
✅ **Security Best Practices Identified** - OAuth 2.0 RFC 9700 compliant
✅ **Architecture Patterns Selected** - Production-ready, scalable design
✅ **Implementation Risks Mitigated** - Circuit breaker, retry, rate limiting
✅ **Testing Strategy Defined** - Real PostgreSQL, TDD approach
✅ **Performance Goals Achievable** - <200ms auth, <50ms validation
✅ **Secrets Management Compliant** - Zero secrets in source code
✅ **Observability Complete** - Metrics, logging, tracing, health checks

**Status**: Ready for Phase 1 (Design & Contracts)
