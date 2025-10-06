# Technical Research: JWT Authentication Service

**Project**: Maliev.AuthService
**Feature**: 001-create-a-jwt
**Date**: 2025-10-05
**Purpose**: Document technical decisions and implementation patterns for .NET 9 JWT authentication service with OAuth 2.0 RFC 9700 compliance

---

## 1. JWT Signing Algorithm (EdDSA vs ES256)

### Decision
**ES256 (ECDSA P-256)** as primary algorithm with potential EdDSA support via third-party library

### Rationale
- **.NET 9 Native Support**: System.Security.Cryptography has full native support for ES256 (ECDSA P-256)
- **EdDSA Limitation**: .NET does not currently support EdDSA natively as Windows doesn't yet support it
- **Industry Standard**: ES256 is widely supported across JWT libraries and services, ensuring broad compatibility
- **Security**: ES256 provides 128-bit security level, sufficient for authentication tokens
- **Performance**: ECDSA signing is faster than RSA while maintaining equivalent security

### Alternatives Considered
- **EdDSA (Ed25519)**: Requires third-party library (ScottBrady.IdentityModel with Bouncy Castle)
  - **Pros**: More modern, slightly better performance, RFC 7518 recommended
  - **Cons**: No native .NET support, adds external dependency
  - **Decision**: Defer to future version if native support is added

- **RS256 (RSA-SHA256)**: Well-established standard
  - **Pros**: Universal support, native .NET implementation
  - **Cons**: Slower than ECDSA, larger key sizes (2048+ bits), older algorithm
  - **Decision**: Rejected in favor of modern ECDSA

- **HS256 (HMAC-SHA256)**: Symmetric algorithm
  - **Pros**: Simplest implementation, fastest performance
  - **Cons**: Requires shared secret across all services, poor key distribution model for microservices
  - **Decision**: Rejected - symmetric keys don't scale for distributed systems

### Implementation

**Key Generation (ES256)**:
```csharp
using System.Security.Cryptography;

// Generate ECDSA key pair for ES256
public class ES256KeyGenerator
{
    public static (string privateKeyPem, string publicKeyPem) GenerateKeyPair()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // Export private key (PEM format)
        var privateKey = ecdsa.ExportECPrivateKeyPem();

        // Export public key (PEM format)
        var publicKey = ecdsa.ExportSubjectPublicKeyInfoPem();

        return (privateKey, publicKey);
    }
}
```

**JWT Signing**:
```csharp
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;

public class JwtGenerator
{
    private readonly ECDsa _ecdsa;

    public JwtGenerator(string privateKeyPem)
    {
        _ecdsa = ECDsa.Create();
        _ecdsa.ImportFromPem(privateKeyPem);
    }

    public string GenerateToken(Dictionary<string, object> claims)
    {
        var securityKey = new ECDsaSecurityKey(_ecdsa) { KeyId = "key-2025-10-05" };
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = credentials,
            Issuer = _jwtOptions.Issuer, // Loaded from /mnt/secrets/jwt-issuer
            Audience = _jwtOptions.Audience // Loaded from /mnt/secrets/jwt-audience
        };

        var handler = new JwtSecurityTokenHandler();
        var token = handler.CreateToken(tokenDescriptor);
        return handler.WriteToken(token);
    }
}
```

**JWT Validation with Algorithm Allowlist**:
```csharp
public class JwtValidator
{
    private readonly ECDsa _ecdsa;

    public JwtValidator(string publicKeyPem)
    {
        _ecdsa = ECDsa.Create();
        _ecdsa.ImportFromPem(publicKeyPem);
    }

    public ClaimsPrincipal ValidateToken(string token)
    {
        var securityKey = new ECDsaSecurityKey(_ecdsa);

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = securityKey,
            ValidAlgorithms = new[] { SecurityAlgorithms.EcdsaSha256 }, // CRITICAL: Algorithm allowlist
            ValidateIssuer = true,
            ValidIssuer = _jwtOptions.Issuer, // Loaded from /mnt/secrets/jwt-issuer
            ValidateAudience = true,
            ValidAudience = _jwtOptions.Audience, // Loaded from /mnt/secrets/jwt-audience
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30) // 30s clock skew tolerance
        };

        var handler = new JwtSecurityTokenHandler();
        return handler.ValidateToken(token, validationParameters, out _);
    }
}
```

### References
- RFC 7518: JSON Web Algorithms (JWA) - https://tools.ietf.org/html/rfc7518
- .NET 9 ECDsa Documentation: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.ecdsa
- ScottBrady91 EdDSA Implementation: https://www.scottbrady.io/c-sharp/eddsa-for-jwt-signing-in-dotnet-core

---

## 2. Refresh Token Rotation & Reuse Detection

### Decision
**Token Family Tracking** with database persistence, automatic rotation, and reuse detection per OAuth 2.0 RFC 9700

### Rationale
- **RFC 9700 Requirement**: For public clients, authorization servers MUST utilize refresh token rotation
- **Security**: Detects stolen tokens by invalidating entire token family when reuse is detected
- **Auditability**: Token family tracking provides complete audit trail of authentication sessions
- **Horizontal Scaling**: Database-backed state enables stateless microservice design

### Alternatives Considered
- **Single Refresh Token Reuse**: Keep same refresh token until expiration
  - **Pros**: Simpler implementation, fewer database writes
  - **Cons**: Violates OAuth 2.0 RFC 9700 for public clients, cannot detect stolen tokens
  - **Decision**: Rejected - security requirement

- **In-Memory Token Tracking**: Store token families in Redis/Memory cache
  - **Pros**: Faster lookups, lower latency
  - **Cons**: Loss of data on restart, complex synchronization across pods
  - **Decision**: Rejected - PostgreSQL provides ACID guarantees needed for security

### Database Schema

**Entity: RefreshToken**
```csharp
public class RefreshToken
{
    public Guid Id { get; set; }
    public string TokenHash { get; set; } // SHA-256 hash (64 hex chars)
    public Guid UserId { get; set; }
    public UserType UserType { get; set; } // Customer or Employee
    public Guid FamilyId { get; set; } // Links tokens in same rotation chain
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public bool IsRevoked { get; set; }
    public bool IsUsed { get; set; } // Set to true when token is refreshed
    public DateTimeOffset? RevokedAt { get; set; }
    public byte[] RowVersion { get; set; } // Optimistic concurrency

    public TokenFamily Family { get; set; } // Navigation property
}
```

**Entity: TokenFamily**
```csharp
public class TokenFamily
{
    public Guid FamilyId { get; set; } // Primary key
    public Guid UserId { get; set; }
    public UserType UserType { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset LastUsedAt { get; set; }

    public ICollection<RefreshToken> Tokens { get; set; } // Navigation
}
```

**EF Core Configuration**:
```csharp
protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    modelBuilder.Entity<RefreshToken>(entity =>
    {
        entity.HasKey(e => e.Id);
        entity.Property(e => e.TokenHash).IsRequired().HasMaxLength(64);
        entity.Property(e => e.RowVersion).IsRowVersion(); // Optimistic concurrency

        // Indexes for performance
        entity.HasIndex(e => e.TokenHash).IsUnique();
        entity.HasIndex(e => e.FamilyId);
        entity.HasIndex(e => new { e.UserId, e.UserType, e.IsRevoked, e.IsUsed });

        // Foreign key to TokenFamily
        entity.HasOne(e => e.Family)
            .WithMany(f => f.Tokens)
            .HasForeignKey(e => e.FamilyId)
            .OnDelete(DeleteBehavior.Cascade);
    });

    modelBuilder.Entity<TokenFamily>(entity =>
    {
        entity.HasKey(e => e.FamilyId);
        entity.HasIndex(e => e.UserId);
    });
}
```

### Reuse Detection Logic

**Service Implementation**:
```csharp
public class RefreshTokenService : IRefreshTokenService
{
    private readonly AuthDbContext _context;
    private readonly ILogger<RefreshTokenService> _logger;

    public async Task<TokenRotationResult> RotateTokenAsync(string providedToken)
    {
        var tokenHash = ComputeSha256Hash(providedToken);

        var existingToken = await _context.RefreshTokens
            .Include(t => t.Family)
            .FirstOrDefaultAsync(t => t.TokenHash == tokenHash);

        if (existingToken == null)
            return TokenRotationResult.InvalidToken();

        // CRITICAL: Reuse detection
        if (existingToken.IsUsed)
        {
            _logger.LogWarning("Refresh token reuse detected for FamilyId: {FamilyId}",
                existingToken.FamilyId);

            // Invalidate entire token family
            await InvalidateTokenFamilyAsync(existingToken.FamilyId);

            return TokenRotationResult.TokenFamilyInvalidated();
        }

        if (existingToken.IsRevoked)
            return TokenRotationResult.TokenRevoked();

        if (existingToken.ExpiresAt < DateTimeOffset.UtcNow)
            return TokenRotationResult.TokenExpired();

        using var transaction = await _context.Database.BeginTransactionAsync();
        try
        {
            // Mark old token as used
            existingToken.IsUsed = true;

            // Generate new refresh token
            var newRefreshToken = GenerateSecureToken(); // 256-bit random
            var newTokenHash = ComputeSha256Hash(newRefreshToken);

            var newToken = new RefreshToken
            {
                Id = Guid.NewGuid(),
                TokenHash = newTokenHash,
                UserId = existingToken.UserId,
                UserType = existingToken.UserType,
                FamilyId = existingToken.FamilyId, // Same family
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddDays(7),
                IsRevoked = false,
                IsUsed = false
            };

            _context.RefreshTokens.Add(newToken);

            // Update family last used time
            existingToken.Family.LastUsedAt = DateTimeOffset.UtcNow;

            await _context.SaveChangesAsync();
            await transaction.CommitAsync();

            return TokenRotationResult.Success(newRefreshToken, existingToken.UserId);
        }
        catch (DbUpdateConcurrencyException)
        {
            await transaction.RollbackAsync();
            _logger.LogWarning("Concurrency conflict during token rotation");
            return TokenRotationResult.ConcurrencyConflict();
        }
    }

    private async Task InvalidateTokenFamilyAsync(Guid familyId)
    {
        var tokensInFamily = await _context.RefreshTokens
            .Where(t => t.FamilyId == familyId && !t.IsRevoked)
            .ToListAsync();

        foreach (var token in tokensInFamily)
        {
            token.IsRevoked = true;
            token.RevokedAt = DateTimeOffset.UtcNow;
        }

        await _context.SaveChangesAsync();
    }
}
```

### References
- OAuth 2.0 RFC 9700: https://datatracker.ietf.org/doc/rfc9700/
- WorkOS OAuth Best Practices: https://workos.com/blog/oauth-best-practices
- Milan Jovanovic on Race Conditions: https://www.milanjovanovic.tech/blog/solving-race-conditions-with-ef-core-optimistic-locking

---

## 3. Distributed Token Revocation

### Decision
**Redis Pub/Sub** for token revocation event distribution with in-memory cache for revocation list

### Rationale
- **Latency**: Sub-millisecond event propagation (meets <2s requirement with margin)
- **Simplicity**: Easier deployment and operation than Kafka/RabbitMQ
- **Cost**: More cost-effective than full message broker for this use case
- **Stateless**: Event-based model aligns with microservice architecture

### Alternatives Considered
- **Apache Kafka**: Durable message log with strong delivery guarantees
  - **Pros**: Exactly-once semantics, message replay, high throughput
  - **Cons**: Higher latency (10-100ms vs <1ms Redis), complex deployment, overkill for simple events
  - **Decision**: Rejected - unnecessary complexity for token revocation

- **RabbitMQ**: Traditional message queue with routing
  - **Pros**: Flexible routing, good delivery guarantees
  - **Cons**: Higher latency than Redis, more operational overhead
  - **Decision**: Rejected - Redis simpler for pub/sub pattern

- **HTTP Push Notifications**: Direct service-to-service calls
  - **Pros**: No additional infrastructure
  - **Cons**: Requires service discovery, no delivery guarantee if service is down, creates coupling
  - **Decision**: Rejected - doesn't scale to 20+ microservices

### Integration Pattern

**Publisher (Auth Service)**:
```csharp
using StackExchange.Redis;

public class TokenRevocationService : ITokenRevocationService
{
    private readonly IConnectionMultiplexer _redis;
    private readonly ILogger<TokenRevocationService> _logger;

    public async Task RevokeAccessTokenAsync(string jti, string reason)
    {
        var revocation = new RevokedAccessToken
        {
            Jti = jti,
            RevokedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(15), // Match access token TTL
            Reason = reason
        };

        // Store in database for persistence
        await _context.RevokedAccessTokens.AddAsync(revocation);
        await _context.SaveChangesAsync();

        // Publish revocation event to all services
        var subscriber = _redis.GetSubscriber();
        var eventData = JsonSerializer.Serialize(new
        {
            Jti = jti,
            RevokedAt = revocation.RevokedAt,
            ExpiresAt = revocation.ExpiresAt
        });

        await subscriber.PublishAsync("token-revocations", eventData);

        _logger.LogInformation("Access token {Jti} revoked. Reason: {Reason}", jti, reason);
    }
}
```

**Subscriber (All Microservices)**:
```csharp
public class TokenRevocationSubscriber : BackgroundService
{
    private readonly IConnectionMultiplexer _redis;
    private readonly IMemoryCache _revocationCache;
    private readonly ILogger<TokenRevocationSubscriber> _logger;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var subscriber = _redis.GetSubscriber();

        await subscriber.SubscribeAsync("token-revocations", (channel, message) =>
        {
            var revocation = JsonSerializer.Deserialize<TokenRevocationEvent>(message);

            // Add to in-memory cache for fast validation
            var cacheExpiration = revocation.ExpiresAt - DateTimeOffset.UtcNow;
            _revocationCache.Set(revocation.Jti, true, cacheExpiration);

            _logger.LogInformation("Received revocation for token {Jti}", revocation.Jti);
        });

        _logger.LogInformation("Subscribed to token-revocations channel");

        await Task.Delay(Timeout.Infinite, stoppingToken);
    }
}
```

**Validation Logic (JWT Middleware)**:
```csharp
public class JwtValidator
{
    private readonly IMemoryCache _revocationCache;

    public async Task<bool> IsTokenRevokedAsync(string jti)
    {
        // Check in-memory cache first (fast path)
        if (_revocationCache.TryGetValue(jti, out bool isRevoked))
            return isRevoked;

        // Fallback to database if cache miss (e.g., service just started)
        var revocation = await _context.RevokedAccessTokens
            .FirstOrDefaultAsync(r => r.Jti == jti && r.ExpiresAt > DateTimeOffset.UtcNow);

        if (revocation != null)
        {
            var cacheExpiration = revocation.ExpiresAt - DateTimeOffset.UtcNow;
            _revocationCache.Set(jti, true, cacheExpiration);
            return true;
        }

        return false;
    }
}
```

### Fallback Strategy
- **Redis Unavailable**: Services fall back to database queries for revocation check
- **Event Delivery Delay**: In-memory cache in each service provides eventual consistency
- **Service Restart**: Revocations are persisted in PostgreSQL, loaded on startup if needed
- **Performance**: <2 second propagation target met by Redis pub/sub latency

### References
- AWS Redis vs Kafka Comparison: https://aws.amazon.com/compare/the-difference-between-kafka-and-redis/
- Redis Pub/Sub Documentation: https://redis.io/glossary/pub-sub/
- Better Stack Redis vs Kafka: https://betterstack.com/community/comparisons/redis-vs-kafka/

---

## 4. SHA-256 Token Hashing

### Decision
**SHA-256 hashing with CryptographicOperations.FixedTimeEquals** for constant-time comparison

### Rationale
- **RFC 6819 Compliance**: Recommends one-way hashing (not encryption) for stored tokens
- **Security**: SHA-256 is irreversible; compromised database doesn't leak tokens
- **Timing Attack Prevention**: FixedTimeEquals prevents timing side-channel attacks
- **.NET Native Support**: CryptographicOperations available since .NET Core 2.1

### Alternatives Considered
- **Token Encryption**: Symmetric encryption (AES) of refresh tokens
  - **Pros**: Tokens are recoverable if needed
  - **Cons**: Reversible (if key is compromised, all tokens are exposed), doesn't align with RFC 6819
  - **Decision**: Rejected - hashing is more secure

- **bcrypt/Argon2**: Password hashing algorithms
  - **Pros**: Designed for password protection, configurable work factor
  - **Cons**: Too slow for token validation (intentionally), unnecessary complexity
  - **Decision**: Rejected - tokens aren't passwords, SHA-256 sufficient

### Implementation

**Token Generation (256-bit random)**:
```csharp
using System.Security.Cryptography;

public static string GenerateSecureToken()
{
    var bytes = new byte[32]; // 256 bits
    using var rng = RandomNumberGenerator.Create();
    rng.GetBytes(bytes);
    return Convert.ToBase64String(bytes);
}
```

**SHA-256 Hashing**:
```csharp
using System.Security.Cryptography;
using System.Text;

public static string ComputeSha256Hash(string token)
{
    var bytes = Encoding.UTF8.GetBytes(token);
    var hashBytes = SHA256.HashData(bytes);
    return Convert.ToHexString(hashBytes).ToLowerInvariant(); // 64 hex characters
}
```

**Constant-Time Comparison**:
```csharp
using System.Security.Cryptography;

public static bool VerifyToken(string providedToken, string storedHash)
{
    var providedHash = ComputeSha256Hash(providedToken);
    var providedHashBytes = Convert.FromHexString(providedHash);
    var storedHashBytes = Convert.FromHexString(storedHash);

    // CRITICAL: Constant-time comparison prevents timing attacks
    return CryptographicOperations.FixedTimeEquals(providedHashBytes, storedHashBytes);
}
```

**Why Constant-Time Matters**:
- **Timing Attack**: Attacker measures response time to guess token bytes
- **Variable-Time Comparison**: `==` or `SequenceEqual` exits early on first mismatch
- **Constant-Time Comparison**: Always processes all bytes regardless of match
- **Security Impact**: Prevents side-channel attack that could reveal token structure

### References
- RFC 6819 OAuth 2.0 Threat Model: https://tools.ietf.org/html/rfc6819
- CryptographicOperations.FixedTimeEquals: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cryptographicoperations.fixedtimeequals
- vcsjones Blog on FixedTimeEquals: https://vcsjones.dev/fixed-time-equals-dotnet-core/

---

## 5. Dual-Factor Rate Limiting

### Decision
**ASP.NET Core 9.0 built-in rate limiting middleware** with two partition policies: account-based and IP-based

### Rationale
- **Native .NET 9 Support**: No third-party dependencies, well-integrated
- **Flexibility**: Partition-based limiting supports multiple strategies
- **Performance**: In-memory state with sliding window algorithm
- **Security**: Dual-factor approach prevents both brute force and distributed attacks

### Alternatives Considered
- **AspNetCoreRateLimit Library**: Third-party middleware
  - **Pros**: More features, Redis-backed distributed state
  - **Cons**: External dependency, .NET 9 has native support now
  - **Decision**: Rejected - native middleware sufficient

- **Single-Factor Limiting**: Account-based only
  - **Pros**: Simpler implementation
  - **Cons**: Doesn't prevent distributed credential stuffing across many accounts
  - **Decision**: Rejected - security requirement

### Implementation

**Program.cs Configuration**:
```csharp
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;

builder.Services.AddRateLimiter(options =>
{
    // Account-based rate limiting: 5 attempts per account, 15 min lockout
    options.AddPolicy("account-limit", context =>
    {
        var username = context.Request.RouteValues["username"]?.ToString()
            ?? context.Request.Headers["X-Username"].ToString();

        return RateLimitPartition.GetSlidingWindowLimiter(
            partitionKey: $"account:{username}",
            factory: _ => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(15),
                SegmentsPerWindow = 3, // 5-minute segments
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0 // No queueing for authentication
            });
    });

    // IP-based rate limiting: 20 attempts per IP, 15 min block
    options.AddPolicy("ip-limit", context =>
    {
        var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        return RateLimitPartition.GetSlidingWindowLimiter(
            partitionKey: $"ip:{ipAddress}",
            factory: _ => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = 20,
                Window = TimeSpan.FromMinutes(15),
                SegmentsPerWindow = 3,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            });
    });

    // Service-to-service rate limiting: 1000 validations/min per service
    options.AddPolicy("service-limit", context =>
    {
        var serviceId = context.Request.Headers["X-Service-ID"].ToString();

        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: $"service:{serviceId}",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 1000,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            });
    });

    options.OnRejected = async (context, cancellationToken) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;

        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            context.HttpContext.Response.Headers.RetryAfter = retryAfter.TotalSeconds.ToString();
        }

        await context.HttpContext.Response.WriteAsJsonAsync(new
        {
            error = "too_many_requests",
            message = "Rate limit exceeded",
            retry_after = retryAfter?.TotalSeconds ?? 900
        }, cancellationToken);
    };
});
```

**Middleware Pipeline**:
```csharp
var app = builder.Build();

app.UseRateLimiter(); // MUST be before UseAuthentication
app.UseAuthentication();
app.UseAuthorization();
```

**Controller Endpoint with Multiple Policies**:
```csharp
[HttpPost("login")]
[EnableRateLimiting("account-limit")] // Apply account-based limit
[EnableRateLimiting("ip-limit")]      // Apply IP-based limit
public async Task<IActionResult> Login([FromBody] LoginRequest request)
{
    // Authentication logic
}
```

**Progressive Delays**:
```csharp
public class ProgressiveDelayService
{
    private readonly IMemoryCache _cache;

    public async Task ApplyProgressiveDelay(string username)
    {
        var cacheKey = $"auth-attempts:{username}";
        var attempts = _cache.GetOrCreate(cacheKey, entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15);
            return 0;
        });

        attempts++;
        _cache.Set(cacheKey, attempts);

        // Progressive delays: 1s → 2s → 4s
        var delay = attempts switch
        {
            >= 5 => 4000,
            4 => 2000,
            3 => 1000,
            _ => 0
        };

        if (delay > 0)
            await Task.Delay(delay);
    }
}
```

**Rate Limit Headers**:
```csharp
public class RateLimitHeadersMiddleware
{
    public async Task InvokeAsync(HttpContext context)
    {
        // Headers added automatically by ASP.NET Core rate limiting:
        // X-RateLimit-Limit: 5
        // X-RateLimit-Remaining: 3
        // X-RateLimit-Reset: 1696500000
        // Retry-After: 900 (when limit exceeded)

        await _next(context);
    }
}
```

### References
- ASP.NET Core 9.0 Rate Limiting: https://learn.microsoft.com/en-us/aspnet/core/performance/rate-limit
- Rate Limiting Samples: https://learn.microsoft.com/en-us/aspnet/core/performance/rate-limit-samples
- .NET Insights Implementation Guide: https://dot-net-insights.com/2025/01/03/how-to-implement-rate-limiting-middleware-in-net/

---

## 6. Circuit Breaker for External Services

### Decision
**Polly 8.x Circuit Breaker** integrated with IHttpClientFactory for typed HTTP clients

### Rationale
- **Resilience**: Fail fast when external services (customer/employee validation) are unavailable
- **Native Integration**: Polly works seamlessly with .NET 9 HttpClient factory
- **Configurability**: Flexible failure thresholds, open duration, and half-open testing
- **Observability**: Circuit state changes can be logged and exposed via health checks

### Alternatives Considered
- **Manual Retry Logic**: Custom error handling with retry counters
  - **Pros**: No external dependency
  - **Cons**: Error-prone, hard to test, lacks circuit breaker pattern
  - **Decision**: Rejected - Polly is battle-tested

- **Kubernetes Liveness/Readiness**: Let orchestration handle failures
  - **Pros**: Platform-level resilience
  - **Cons**: Doesn't prevent cascading failures, restarts entire pod (too coarse)
  - **Decision**: Complementary - use both

### Implementation

**NuGet Packages**:
```xml
<PackageReference Include="Polly" Version="8.6.4" />
<PackageReference Include="Microsoft.Extensions.Http.Polly" Version="9.0.0" />
```

**Circuit Breaker Configuration**:
```csharp
using Polly;
using Polly.CircuitBreaker;
using Polly.Extensions.Http;

public static class CircuitBreakerPolicies
{
    public static IAsyncPolicy<HttpResponseMessage> GetCircuitBreakerPolicy(
        string serviceName, ILogger logger)
    {
        return HttpPolicyExtensions
            .HandleTransientHttpError() // 5xx and 408
            .OrResult(msg => msg.StatusCode == System.Net.HttpStatusCode.ServiceUnavailable)
            .AdvancedCircuitBreakerAsync(
                failureThreshold: 0.5,        // 50% failure rate
                samplingDuration: TimeSpan.FromSeconds(10),
                minimumThroughput: 5,         // At least 5 requests
                durationOfBreak: TimeSpan.FromSeconds(30),
                onBreak: (outcome, duration) =>
                {
                    logger.LogWarning(
                        "Circuit breaker opened for {ServiceName}. Duration: {Duration}s",
                        serviceName, duration.TotalSeconds);
                },
                onReset: () =>
                {
                    logger.LogInformation("Circuit breaker closed for {ServiceName}", serviceName);
                },
                onHalfOpen: () =>
                {
                    logger.LogInformation("Circuit breaker half-open for {ServiceName}", serviceName);
                });
    }
}
```

**Program.cs Registration**:
```csharp
builder.Services.AddHttpClient<ICustomerValidationService, CustomerValidationService>(client =>
{
    var baseUrl = builder.Configuration["ExternalServices:CustomerValidationUrl"];
    client.BaseAddress = new Uri(baseUrl);
    client.Timeout = TimeSpan.FromSeconds(5);
})
.AddPolicyHandler((services, request) =>
{
    var logger = services.GetRequiredService<ILogger<Program>>();
    return CircuitBreakerPolicies.GetCircuitBreakerPolicy("CustomerService", logger);
})
.AddPolicyHandler(Policy.TimeoutAsync<HttpResponseMessage>(TimeSpan.FromSeconds(5))); // Timeout policy

builder.Services.AddHttpClient<IEmployeeValidationService, EmployeeValidationService>(client =>
{
    var baseUrl = builder.Configuration["ExternalServices:EmployeeValidationUrl"];
    client.BaseAddress = new Uri(baseUrl);
    client.Timeout = TimeSpan.FromSeconds(5);
})
.AddPolicyHandler((services, request) =>
{
    var logger = services.GetRequiredService<ILogger<Program>>();
    return CircuitBreakerPolicies.GetCircuitBreakerPolicy("EmployeeService", logger);
})
.AddPolicyHandler(Policy.TimeoutAsync<HttpResponseMessage>(TimeSpan.FromSeconds(5)));
```

**Service Implementation**:
```csharp
public class CustomerValidationService : ICustomerValidationService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<CustomerValidationService> _logger;

    public CustomerValidationService(HttpClient httpClient, ILogger<CustomerValidationService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<ValidationResult> ValidateCredentialsAsync(string username, string password)
    {
        try
        {
            var response = await _httpClient.PostAsJsonAsync("/validate", new
            {
                username,
                password
            });

            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<ValidationResult>();
                return result;
            }

            return ValidationResult.Invalid();
        }
        catch (BrokenCircuitException ex)
        {
            _logger.LogError(ex, "Circuit breaker open for CustomerService");
            throw new ExternalServiceUnavailableException("Customer validation service is unavailable", ex);
        }
        catch (TimeoutRejectedException ex)
        {
            _logger.LogError(ex, "Timeout calling CustomerService");
            throw new ExternalServiceUnavailableException("Customer validation service timeout", ex);
        }
    }
}
```

**Health Check Integration**:
```csharp
public class ExternalServiceHealthCheck : IHealthCheck
{
    private readonly IHttpClientFactory _httpClientFactory;

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var client = _httpClientFactory.CreateClient(nameof(CustomerValidationService));

        try
        {
            var response = await client.GetAsync("/health", cancellationToken);

            if (response.IsSuccessStatusCode)
                return HealthCheckResult.Healthy("CustomerService is healthy");

            return HealthCheckResult.Degraded($"CustomerService returned {response.StatusCode}");
        }
        catch (BrokenCircuitException)
        {
            return HealthCheckResult.Unhealthy("CustomerService circuit breaker is open");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("CustomerService is unreachable", ex);
        }
    }
}
```

### References
- Polly Documentation: https://github.com/App-vNext/Polly
- Microsoft Circuit Breaker Pattern: https://learn.microsoft.com/en-us/dotnet/architecture/microservices/implement-resilient-applications/implement-circuit-breaker-pattern
- Building Resilient Microservices with Polly: https://atalupadhyay.wordpress.com/2025/03/09/building-resilient-microservices-with-pollys-circuit-breaker-in-net-core/

---

## 7. OpenTelemetry Distributed Tracing

### Decision
**OpenTelemetry .NET SDK** with ASP.NET Core instrumentation, correlation ID middleware, and Prometheus exporter

### Rationale
- **Industry Standard**: OpenTelemetry is vendor-neutral, supported by all major observability platforms
- **.NET 9 Integration**: Native support in ASP.NET Core with automatic activity creation
- **Correlation ID Propagation**: W3C Trace Context standard ensures cross-service tracing
- **Metrics + Traces**: Unified telemetry SDK for both Prometheus metrics and distributed traces

### Alternatives Considered
- **Application Insights**: Microsoft's observability platform
  - **Pros**: Deep .NET integration, Azure ecosystem
  - **Cons**: Vendor lock-in, requires Azure
  - **Decision**: Rejected - OpenTelemetry provides vendor neutrality

- **Custom Correlation ID**: Manual propagation via middleware
  - **Pros**: Simple implementation
  - **Cons**: Doesn't provide trace spans, no parent-child relationships, not standardized
  - **Decision**: Rejected - OpenTelemetry provides richer data

### Implementation

**NuGet Packages**:
```xml
<PackageReference Include="OpenTelemetry" Version="1.10.0" />
<PackageReference Include="OpenTelemetry.Exporter.Prometheus.AspNetCore" Version="1.10.0" />
<PackageReference Include="OpenTelemetry.Instrumentation.AspNetCore" Version="1.10.0" />
<PackageReference Include="OpenTelemetry.Instrumentation.Http" Version="1.10.0" />
<PackageReference Include="OpenTelemetry.Extensions.Hosting" Version="1.10.0" />
```

**Program.cs Configuration**:
```csharp
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

builder.Services.AddOpenTelemetry()
    .ConfigureResource(resource => resource
        .AddService("maliev-auth-service", serviceVersion: "1.0.0"))
    .WithTracing(tracing => tracing
        .AddAspNetCoreInstrumentation(options =>
        {
            options.RecordException = true;
            options.EnrichWithHttpRequest = (activity, request) =>
            {
                // Add custom tags
                activity.SetTag("http.client_ip", request.HttpContext.Connection.RemoteIpAddress);
                activity.SetTag("http.user_agent", request.Headers.UserAgent.ToString());
            };
        })
        .AddHttpClientInstrumentation(options =>
        {
            options.RecordException = true;
            options.EnrichWithHttpRequestMessage = (activity, request) =>
            {
                activity.SetTag("http.target_service", request.RequestUri?.Host);
            };
        })
        .AddSource("Maliev.AuthService") // Custom activity source
        .AddConsoleExporter()) // For development
    .WithMetrics(metrics => metrics
        .AddAspNetCoreInstrumentation()
        .AddHttpClientInstrumentation()
        .AddPrometheusExporter());

// Prometheus scrape endpoint
app.MapPrometheusScrapingEndpoint("/metrics");
```

**Correlation ID Middleware**:
```csharp
public class CorrelationIdMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<CorrelationIdMiddleware> _logger;

    public async Task InvokeAsync(HttpContext context)
    {
        // Extract or generate correlation ID
        var correlationId = context.Request.Headers["X-Correlation-ID"].FirstOrDefault()
            ?? context.Request.Headers["X-Request-ID"].FirstOrDefault()
            ?? Activity.Current?.TraceId.ToString()
            ?? Guid.NewGuid().ToString();

        // Add to HttpContext for access in controllers
        context.Items["CorrelationId"] = correlationId;

        // Add to response headers
        context.Response.Headers.Append("X-Correlation-ID", correlationId);

        // Add to current activity (OpenTelemetry span)
        Activity.Current?.SetTag("correlation.id", correlationId);

        // Add to logger scope (appears in all logs for this request)
        using (_logger.BeginScope(new Dictionary<string, object>
        {
            ["CorrelationId"] = correlationId
        }))
        {
            await _next(context);
        }
    }
}
```

**Custom Activity Source for Business Logic**:
```csharp
using System.Diagnostics;

public class AuthenticationService : IAuthenticationService
{
    private static readonly ActivitySource ActivitySource = new("Maliev.AuthService");
    private readonly ILogger<AuthenticationService> _logger;

    public async Task<LoginResponse> AuthenticateAsync(LoginRequest request)
    {
        using var activity = ActivitySource.StartActivity("AuthenticateUser", ActivityKind.Internal);
        activity?.SetTag("user.type", request.UserType);
        activity?.SetTag("user.username", request.Username);

        try
        {
            // Validate credentials (auto-instrumented HttpClient call creates child span)
            var validationResult = await _externalValidationService.ValidateAsync(request);

            if (!validationResult.IsValid)
            {
                activity?.SetStatus(ActivityStatusCode.Error, "Invalid credentials");
                activity?.SetTag("auth.result", "failure");
                return LoginResponse.Failure();
            }

            // Generate tokens (child span)
            using var tokenActivity = ActivitySource.StartActivity("GenerateTokens", ActivityKind.Internal);
            var tokens = await _tokenGenerator.GenerateTokenPairAsync(validationResult.UserId);

            activity?.SetTag("auth.result", "success");
            activity?.SetTag("token.family_id", tokens.FamilyId);

            return LoginResponse.Success(tokens);
        }
        catch (Exception ex)
        {
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            activity?.RecordException(ex);
            throw;
        }
    }
}
```

**W3C Trace Context Propagation (Automatic)**:
```
// Incoming request headers (auto-parsed by OpenTelemetry):
traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
tracestate: congo=t61rcWkgMzE

// Outgoing HttpClient requests (auto-injected by OpenTelemetry):
traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-b9c7c989f97918e1-01
```

**Serilog Integration**:
```csharp
using Serilog.Context;

// In CorrelationIdMiddleware or controller:
LogContext.PushProperty("TraceId", Activity.Current?.TraceId.ToString());
LogContext.PushProperty("SpanId", Activity.Current?.SpanId.ToString());

_logger.LogInformation("User {Username} authenticated successfully");
// Log output includes: TraceId="4bf92f3577b34da6a3ce929d0e0e4736" SpanId="00f067aa0ba902b7"
```

### References
- OpenTelemetry .NET Documentation: https://opentelemetry.io/docs/languages/dotnet/
- ASP.NET Core Distributed Tracing: https://developmentwithadot.blogspot.com/2025/01/aspnet-core-distributed-tracing.html
- Microsoft .NET Observability Guide: https://learn.microsoft.com/en-us/dotnet/core/diagnostics/observability-with-otel

---

## 8. Database Optimistic Concurrency

### Decision
**EF Core RowVersion concurrency token** with automatic retry logic for race condition handling

### Rationale
- **Race Condition Prevention**: Prevents lost updates during concurrent token rotation
- **PostgreSQL Support**: Npgsql EF Core provider supports xmin system column for concurrency
- **Automatic Detection**: EF Core automatically detects conflicts and throws DbUpdateConcurrencyException
- **Performance**: Optimistic locking avoids database locks, better for high-throughput scenarios

### Alternatives Considered
- **Pessimistic Locking**: Use database row locks (SELECT FOR UPDATE)
  - **Pros**: Guaranteed no conflicts
  - **Cons**: Reduced concurrency, deadlock potential, doesn't align with stateless microservices
  - **Decision**: Rejected - optimistic locking scales better

- **No Concurrency Control**: Last write wins
  - **Pros**: Simplest implementation
  - **Cons**: Data loss during concurrent updates, security risk for token rotation
  - **Decision**: Rejected - unacceptable for financial/security data

### Implementation

**Entity Configuration (PostgreSQL xmin)**:
```csharp
public class RefreshToken
{
    public Guid Id { get; set; }
    public string TokenHash { get; set; }
    public Guid UserId { get; set; }
    public Guid FamilyId { get; set; }
    public bool IsUsed { get; set; }
    public bool IsRevoked { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }

    // Concurrency token (auto-updated by PostgreSQL)
    public uint Version { get; set; }
}

// EF Core configuration
protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    modelBuilder.Entity<RefreshToken>(entity =>
    {
        // PostgreSQL xmin system column for concurrency
        entity.Property(e => e.Version)
            .IsRowVersion() // Marks as concurrency token
            .HasColumnName("xmin")
            .HasColumnType("xid")
            .ValueGeneratedOnAddOrUpdate(); // Auto-updated by PostgreSQL
    });
}
```

**Alternative: SQL Server rowversion**:
```csharp
public class RefreshToken
{
    // ... other properties

    public byte[] RowVersion { get; set; } // SQL Server rowversion
}

protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    modelBuilder.Entity<RefreshToken>(entity =>
    {
        entity.Property(e => e.RowVersion)
            .IsRowVersion(); // Maps to SQL Server rowversion type
    });
}
```

**Service with Retry Logic**:
```csharp
public class RefreshTokenService : IRefreshTokenService
{
    private readonly AuthDbContext _context;
    private readonly ILogger<RefreshTokenService> _logger;

    public async Task<TokenRotationResult> RotateTokenAsync(string providedToken)
    {
        const int maxRetries = 3;
        int attempt = 0;

        while (attempt < maxRetries)
        {
            try
            {
                attempt++;

                var tokenHash = ComputeSha256Hash(providedToken);
                var existingToken = await _context.RefreshTokens
                    .Include(t => t.Family)
                    .FirstOrDefaultAsync(t => t.TokenHash == tokenHash);

                if (existingToken == null)
                    return TokenRotationResult.InvalidToken();

                // Reuse detection
                if (existingToken.IsUsed)
                {
                    await InvalidateTokenFamilyAsync(existingToken.FamilyId);
                    return TokenRotationResult.TokenFamilyInvalidated();
                }

                // Mark old token as used
                existingToken.IsUsed = true;

                // Generate new token
                var newRefreshToken = GenerateSecureToken();
                var newTokenHash = ComputeSha256Hash(newRefreshToken);

                var newToken = new RefreshToken
                {
                    Id = Guid.NewGuid(),
                    TokenHash = newTokenHash,
                    UserId = existingToken.UserId,
                    UserType = existingToken.UserType,
                    FamilyId = existingToken.FamilyId,
                    CreatedAt = DateTimeOffset.UtcNow,
                    ExpiresAt = DateTimeOffset.UtcNow.AddDays(7),
                    IsRevoked = false,
                    IsUsed = false
                };

                _context.RefreshTokens.Add(newToken);
                existingToken.Family.LastUsedAt = DateTimeOffset.UtcNow;

                // SaveChanges checks RowVersion and throws if modified
                await _context.SaveChangesAsync();

                _logger.LogInformation("Token rotated successfully for UserId: {UserId}", existingToken.UserId);
                return TokenRotationResult.Success(newRefreshToken, existingToken.UserId);
            }
            catch (DbUpdateConcurrencyException ex)
            {
                _logger.LogWarning(ex,
                    "Concurrency conflict during token rotation (attempt {Attempt}/{MaxRetries})",
                    attempt, maxRetries);

                // Detach entities and retry
                foreach (var entry in _context.ChangeTracker.Entries())
                {
                    entry.State = EntityState.Detached;
                }

                if (attempt >= maxRetries)
                {
                    _logger.LogError("Max retries exceeded for token rotation");
                    return TokenRotationResult.ConcurrencyConflict();
                }

                // Exponential backoff before retry
                await Task.Delay(TimeSpan.FromMilliseconds(Math.Pow(2, attempt) * 100));
            }
        }

        return TokenRotationResult.ConcurrencyConflict();
    }
}
```

**How It Works**:
1. **Load**: EF Core loads entity with current RowVersion value
2. **Modify**: Application modifies entity properties
3. **SaveChanges**: EF Core generates UPDATE with WHERE clause checking RowVersion
   ```sql
   UPDATE refresh_tokens
   SET is_used = true, version = version + 1
   WHERE id = '...' AND version = 42; -- Version from step 1
   ```
4. **Conflict Detection**: If another request modified the row (version changed), UPDATE affects 0 rows
5. **Exception**: EF Core throws DbUpdateConcurrencyException
6. **Retry**: Service detaches entities and retries from step 1

### References
- EF Core Concurrency Documentation: https://learn.microsoft.com/en-us/ef/core/saving/concurrency
- Milan Jovanovic on EF Core Optimistic Locking: https://www.milanjovanovic.tech/blog/solving-race-conditions-with-ef-core-optimistic-locking
- Npgsql Concurrency Tokens: https://www.npgsql.org/efcore/modeling/concurrency.html

---

## Summary

This research document provides comprehensive technical implementation patterns for the JWT authentication service. All decisions align with:
- OAuth 2.0 RFC 9700 security best practices
- .NET 9 and ASP.NET Core 9.0 capabilities
- Maliev microservice architecture standards
- Production-ready scalability and observability requirements

**Next Steps**: Proceed to Phase 1 to create data-model.md, contracts/openapi.yaml, and quickstart.md based on these research findings.
