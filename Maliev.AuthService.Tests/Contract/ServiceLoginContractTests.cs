using System.Net;
using System.Net.Http.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Net.Http.Headers;
using Maliev.AuthService.Domain.Entities;
using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Infrastructure.Security;
using Maliev.AuthService.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

[Collection("AuthService Collection")]
public class ServiceLoginContractTests : IntegrationTestBase
{
    public ServiceLoginContractTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_ValidCredentials_Returns200WithServiceToken()
    {
        await CleanDatabaseAsync();
        // Arrange
        var request = new
        {
            client_id = "service-dev-customer-api",
            client_secret = TestConstants.DummyValidServiceSecret,
            service_name = "Attacker Service",
            sub = "system:service:attacker",
            audience = "attacker-audience",
            permissions = new[] { "*" }
        };

        // Act
        var response = await Client.PostAsJsonAsync("/auth/v1/service/login", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.Equal(
            ["access_token", "expires_in", "token_type", "user"],
            json.RootElement.EnumerateObject().Select(property => property.Name).Order());

        Assert.NotNull(json.RootElement.GetProperty("access_token").GetString());
        Assert.NotEmpty(json.RootElement.GetProperty("access_token").GetString()!);
        Assert.Equal("Bearer", json.RootElement.GetProperty("token_type").GetString());
        Assert.True(json.RootElement.GetProperty("expires_in").GetInt32() > 0);

        // Service tokens should not have refresh tokens
        Assert.False(json.RootElement.TryGetProperty("refresh_token", out _));
        var user = json.RootElement.GetProperty("user");
        Assert.Equal(
            ["customer_id", "email", "name", "principal_id", "profile_image_url", "user_id", "user_type"],
            user.EnumerateObject().Select(property => property.Name).Order());
        Assert.Equal("service-dev-customer-api", user.GetProperty("user_id").GetString());
        Assert.Equal("11111111-1111-1111-1111-111111111111", user.GetProperty("principal_id").GetString());
        Assert.Equal("service", user.GetProperty("user_type").GetString());
        Assert.Equal("Customer API Service", user.GetProperty("name").GetString());
        Assert.Equal(JsonValueKind.Null, user.GetProperty("customer_id").ValueKind);
        Assert.Equal(JsonValueKind.Null, user.GetProperty("email").ValueKind);
        Assert.Equal(JsonValueKind.Null, user.GetProperty("profile_image_url").ValueKind);

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(
            json.RootElement.GetProperty("access_token").GetString());
        Assert.False(string.IsNullOrWhiteSpace(jwt.Header.Kid));
        Assert.Equal("test-issuer", jwt.Issuer);
        Assert.Contains("test-audience", jwt.Audiences);
        Assert.Equal(900, json.RootElement.GetProperty("expires_in").GetInt32());
        Assert.Equal(900, long.Parse(jwt.Claims.Single(c => c.Type == "exp").Value) -
            long.Parse(jwt.Claims.Single(c => c.Type == "iat").Value));
        Assert.Equal("11111111-1111-1111-1111-111111111111", jwt.Subject);
        Assert.Equal("service-dev-customer-api", jwt.Claims.Single(c => c.Type == "client_id").Value);
        Assert.Equal("Customer API Service", jwt.Claims.Single(c => c.Type == "service_name").Value);
        Assert.DoesNotContain(jwt.Claims, claim =>
            claim.Type == "permissions" && claim.Value == "*");
        Assert.Equal(1, Factory.TokenIssuanceResolutionCalls);
        Assert.Equal(0, Factory.LegacyIamResolutionCalls);

        using var permissionRequest = JsonDocument.Parse(Factory.LastTokenIssuanceRequestBody!);
        Assert.Equal(
            ["principalId"],
            permissionRequest.RootElement.EnumerateObject().Select(property => property.Name));
        Assert.Equal(
            "11111111-1111-1111-1111-111111111111",
            permissionRequest.RootElement.GetProperty("principalId").GetString());

        var capability = new JwtSecurityTokenHandler().ReadJwtToken(Factory.LastTokenIssuanceAuthorization);
        Assert.Equal("auth-capability-test-key", capability.Header.Kid);
        Assert.Equal([TokenIssuanceCapabilityOptions.Audience], capability.Audiences);
        Assert.Equal(
            "iam.permission-resolution",
            capability.Claims.Single(claim => claim.Type == "purpose").Value);
        Assert.Equal(
            "11111111-1111-1111-1111-111111111111",
            capability.Claims.Single(claim => claim.Type == "target_principal_id").Value);
        Assert.Equal(
            ["iam.auth.resolve-permissions"],
            capability.Claims.Where(claim => claim.Type == "permissions").Select(claim => claim.Value));
        Assert.DoesNotContain(capability.Claims, claim => claim.Type is "role" or "roles");
        Assert.DoesNotContain(capability.Claims, claim => claim.Value == "*");
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_InvalidClientId_Returns401()
    {
        await CleanDatabaseAsync();
        // Arrange - Use properly formatted but non-existent client ID
        var request = new
        {
            client_id = "service-dev-nonexistent",
            client_secret = TestConstants.DummySecret
        };

        // Act
        var response = await Client.PostAsJsonAsync("/auth/v1/service/login", request);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.NotNull(json.RootElement.GetProperty("error").GetString());
        Assert.NotEmpty(json.RootElement.GetProperty("error").GetString()!);
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_InvalidClientSecret_Returns401()
    {
        await CleanDatabaseAsync();
        // Arrange
        var request = new
        {
            client_id = "service-dev-customer-api",
            client_secret = TestConstants.DummyWrongSecret
        };

        // Act
        var response = await Client.PostAsJsonAsync("/auth/v1/service/login", request);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_OversizedBody_Returns413BeforeAuthentication()
    {
        await CleanDatabaseAsync();
        var oversizedJson = JsonSerializer.Serialize(new
        {
            client_id = "service-dev-customer-api",
            client_secret = TestConstants.DummyValidServiceSecret,
            padding = new string('x', 5000)
        });
        using var content = new StringContent(oversizedJson, Encoding.UTF8);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        var response = await Client.PostAsync("/auth/v1/service/login", content);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Equal(0, Factory.IamResolutionCalls);
    }

    [Fact]
    public async Task ServiceLoginRateLimiter_RealRedis_IsolatesClientsBehindSamePeerAndEnforcesThreshold()
    {
        await CleanDatabaseAsync();
        var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__redis")
            ?? throw new InvalidOperationException("The Redis Testcontainer connection is unavailable");
        await using var firstRedis = await StackExchange.Redis.ConnectionMultiplexer
            .ConnectAsync(connectionString);
        await using var secondRedis = await StackExchange.Redis.ConnectionMultiplexer
            .ConnectAsync(connectionString);
        Assert.NotSame(firstRedis, secondRedis);
        var limiterOptions = Options.Create(new ServiceLoginRateLimitOptions
        {
            PeerPermitLimit = 5,
            ClientPermitLimit = 3,
            WindowSeconds = 60
        });
        var firstLimiter = new RedisServiceLoginRateLimiter(
            firstRedis,
            limiterOptions,
            NullLogger<RedisServiceLoginRateLimiter>.Instance);
        var secondLimiter = new RedisServiceLoginRateLimiter(
            secondRedis,
            limiterOptions,
            NullLogger<RedisServiceLoginRateLimiter>.Instance);

        var first = await firstLimiter.TryAcquireAsync("service-a", IPAddress.Loopback);
        var second = await secondLimiter.TryAcquireAsync("service-a", IPAddress.Loopback);
        var third = await firstLimiter.TryAcquireAsync("service-a", IPAddress.Loopback);

        var denied = await secondLimiter.TryAcquireAsync("service-a", IPAddress.Loopback);
        var independentClient = await firstLimiter.TryAcquireAsync("service-b", IPAddress.Loopback);

        Assert.All([first, second, third], result =>
        {
            Assert.True(result.IsAvailable);
            Assert.True(result.IsAllowed);
        });
        Assert.True(denied.IsAvailable);
        Assert.False(denied.IsAllowed);
        Assert.InRange(denied.RetryAfterSeconds, 1, 60);
        Assert.True(independentClient.IsAllowed);

        var server = firstRedis.GetServer(firstRedis.GetEndPoints().First());
        var keys = server.Keys(pattern: "auth:{service-login-rate}:*").Select(key => key.ToString()).ToList();
        Assert.NotEmpty(keys);
        Assert.All(keys, key =>
        {
            Assert.DoesNotContain("service-a", key, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("service-b", key, StringComparison.OrdinalIgnoreCase);
            Assert.Matches("^auth:\\{service-login-rate\\}:(peer|client):[0-9a-f]{64}$", key);
        });
    }

    [Fact]
    public async Task ServiceLoginRateLimiter_RotatingClientIds_CannotBypassPeerCeiling()
    {
        await CleanDatabaseAsync();
        using var scope = Factory.Services.CreateScope();
        var limiter = scope.ServiceProvider.GetRequiredService<IServiceLoginRateLimiter>();

        for (var attempt = 0; attempt < 3; attempt++)
        {
            var allowed = await limiter.TryAcquireAsync($"service-rotated-{attempt}", IPAddress.Loopback);
            Assert.True(allowed.IsAllowed);
        }

        var denied = await limiter.TryAcquireAsync("service-rotated-3", IPAddress.Loopback);

        Assert.True(denied.IsAvailable);
        Assert.False(denied.IsAllowed);
        Assert.InRange(denied.RetryAfterSeconds, 1, 60);
    }

    [Fact]
    public async Task ServiceLoginRateLimiter_RotatingPeers_CannotBypassClientCeiling()
    {
        await CleanDatabaseAsync();
        using var scope = Factory.Services.CreateScope();
        var limiter = scope.ServiceProvider.GetRequiredService<IServiceLoginRateLimiter>();

        for (var attempt = 1; attempt <= 3; attempt++)
        {
            var allowed = await limiter.TryAcquireAsync(
                "service-fixed-client",
                IPAddress.Parse($"192.0.2.{attempt}"));
            Assert.True(allowed.IsAllowed);
        }

        var denied = await limiter.TryAcquireAsync(
            "service-fixed-client",
            IPAddress.Parse("192.0.2.4"));

        Assert.True(denied.IsAvailable);
        Assert.False(denied.IsAllowed);
        Assert.InRange(denied.RetryAfterSeconds, 1, 60);
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_WhenRedisThresholdExceeded_Returns429WithRetryAfter()
    {
        await CleanDatabaseAsync();
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var response = await Client.PostAsJsonAsync("/auth/v1/service/login", new
            {
                client_id = "service-dev-customer-api",
                client_secret = TestConstants.DummyWrongSecret
            });
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        var denied = await Client.PostAsJsonAsync("/auth/v1/service/login", new
        {
            client_id = "service-dev-customer-api",
            client_secret = TestConstants.DummyWrongSecret
        });

        Assert.Equal(HttpStatusCode.TooManyRequests, denied.StatusCode);
        Assert.True(denied.Headers.TryGetValues("Retry-After", out var retryAfter));
        Assert.True(int.Parse(Assert.Single(retryAfter)) > 0);
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_CrossServiceSwappedSecrets_ReturnsIndistinguishable401()
    {
        await CleanDatabaseAsync();
        const string secondClientId = "service-dev-order-api";
        const string secondSecret = "dummy_order_service_secret_456";
        await using (var context = Factory.GetDbContext())
        {
            context.ServiceCredentials.Add(new ServiceCredential
            {
                Id = Guid.NewGuid(),
                ClientId = secondClientId,
                PrincipalId = Guid.NewGuid(),
                ClientSecretHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secondSecret)))
                    .ToLowerInvariant(),
                ServiceName = "Order API Service",
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            });
            await context.SaveChangesAsync();
        }

        var firstWithSecondSecret = await Client.PostAsJsonAsync("/auth/v1/service/login", new
        {
            client_id = "service-dev-customer-api",
            client_secret = secondSecret
        });
        var secondWithFirstSecret = await Client.PostAsJsonAsync("/auth/v1/service/login", new
        {
            client_id = secondClientId,
            client_secret = TestConstants.DummyValidServiceSecret
        });

        Assert.Equal(HttpStatusCode.Unauthorized, firstWithSecondSecret.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, secondWithFirstSecret.StatusCode);
        Assert.Equal(
            await firstWithSecondSecret.Content.ReadAsStringAsync(),
            await secondWithFirstSecret.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_CredentialWithoutIamPrincipal_Returns503WithoutToken()
    {
        await CleanDatabaseAsync();
        const string clientId = "service-dev-unmapped-api";
        const string secret = "dummy_unmapped_service_secret_789";
        await using (var context = Factory.GetDbContext())
        {
            context.ServiceCredentials.Add(new ServiceCredential
            {
                Id = Guid.NewGuid(),
                ClientId = clientId,
                PrincipalId = null,
                ClientSecretHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secret)))
                    .ToLowerInvariant(),
                ServiceName = "Unmapped API Service",
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            });
            await context.SaveChangesAsync();
        }

        var response = await Client.PostAsJsonAsync("/auth/v1/service/login", new
        {
            client_id = clientId,
            client_secret = secret
        });

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(
            ["details", "error", "error_description", "errors", "locked_until"],
            json.RootElement.EnumerateObject().Select(property => property.Name).Order());
        Assert.Equal("service_unavailable", json.RootElement.GetProperty("error").GetString());
        Assert.Equal(
            "Service authentication is temporarily unavailable",
            json.RootElement.GetProperty("error_description").GetString());
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("details").ValueKind);
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("errors").ValueKind);
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("locked_until").ValueKind);
        Assert.False(json.RootElement.TryGetProperty("access_token", out _));
        Assert.Equal(0, Factory.TokenIssuanceResolutionCalls);
        Assert.Equal(0, Factory.LegacyIamResolutionCalls);
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_NonexistentIamPrincipal_Returns503WithoutToken()
    {
        await CleanDatabaseAsync();
        const string clientId = "service-dev-orphaned-api";
        const string secret = "dummy_orphaned_service_secret_012";
        await using (var context = Factory.GetDbContext())
        {
            context.ServiceCredentials.Add(new ServiceCredential
            {
                Id = Guid.NewGuid(),
                ClientId = clientId,
                PrincipalId = TestWebApplicationFactory.NonexistentIamPrincipalId,
                ClientSecretHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secret)))
                    .ToLowerInvariant(),
                ServiceName = "Orphaned API Service",
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            });
            await context.SaveChangesAsync();
        }

        var response = await Client.PostAsJsonAsync("/auth/v1/service/login", new
        {
            client_id = clientId,
            client_secret = secret
        });

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(
            ["details", "error", "error_description", "errors", "locked_until"],
            json.RootElement.EnumerateObject().Select(property => property.Name).Order());
        Assert.Equal("service_unavailable", json.RootElement.GetProperty("error").GetString());
        Assert.Equal(
            "Service authentication is temporarily unavailable",
            json.RootElement.GetProperty("error_description").GetString());
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("details").ValueKind);
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("errors").ValueKind);
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("locked_until").ValueKind);
        Assert.False(json.RootElement.TryGetProperty("access_token", out _));
        Assert.Equal(1, Factory.TokenIssuanceResolutionCalls);
        Assert.Equal(0, Factory.LegacyIamResolutionCalls);
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_MissingCapabilityKey_ReturnsSanitized503WithoutToken()
    {
        await CleanDatabaseAsync();
        using var scope = Factory.Services.CreateScope();
        var options = scope.ServiceProvider
            .GetRequiredService<IOptions<TokenIssuanceCapabilityOptions>>()
            .Value;
        var originalPrivateKey = options.PrivateKey;
        try
        {
            options.PrivateKey = null;

            var response = await Client.PostAsJsonAsync("/auth/v1/service/login", new
            {
                client_id = "service-dev-customer-api",
                client_secret = TestConstants.DummyValidServiceSecret
            });

            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.Equal(
                ["details", "error", "error_description", "errors", "locked_until"],
                json.RootElement.EnumerateObject().Select(property => property.Name).Order());
            Assert.Equal("service_unavailable", json.RootElement.GetProperty("error").GetString());
            Assert.Equal(
                "Service authentication is temporarily unavailable",
                json.RootElement.GetProperty("error_description").GetString());
            Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("details").ValueKind);
            Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("errors").ValueKind);
            Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("locked_until").ValueKind);
            Assert.False(json.RootElement.TryGetProperty("access_token", out _));
            Assert.Equal(0, Factory.TokenIssuanceResolutionCalls);
            Assert.Equal(0, Factory.LegacyIamResolutionCalls);
        }
        finally
        {
            options.PrivateKey = originalPrivateKey;
        }
    }
}
