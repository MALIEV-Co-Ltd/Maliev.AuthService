using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Maliev.AuthService.Tests.Infrastructure;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

[Collection("AuthService Collection")]
public class AuthenticationContractTests : IntegrationTestBase
{
    public AuthenticationContractTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task POST_V1_Auth_Login_ValidCustomerCredentials_Returns200WithTokens()
    {
        await CleanDatabaseAsync();
        // Arrange
        var request = new
        {
            username = "customer@example.com",
            password = "ValidPassword123!",
            user_type = "customer"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/auth/v1/login", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.NotNull(json.RootElement.GetProperty("access_token").GetString());
        Assert.NotEmpty(json.RootElement.GetProperty("access_token").GetString()!);
        Assert.NotNull(json.RootElement.GetProperty("refresh_token").GetString());
        Assert.NotEmpty(json.RootElement.GetProperty("refresh_token").GetString()!);
        Assert.Equal("Bearer", json.RootElement.GetProperty("token_type").GetString());
        Assert.Equal(900, json.RootElement.GetProperty("expires_in").GetInt32()); // 15 minutes

        var user = json.RootElement.GetProperty("user");
        Assert.NotNull(user.GetProperty("user_id").GetString());
        Assert.NotEmpty(user.GetProperty("user_id").GetString()!);
        Assert.Equal("customer", user.GetProperty("user_type").GetString());
    }

    [Fact]
    public async Task POST_V1_Auth_Login_ValidEmployeeCredentials_Returns200WithCorrectUserType()
    {
        await CleanDatabaseAsync();
        // Arrange
        var request = new
        {
            username = "employee@maliev.com",
            password = "ValidPassword123!",
            user_type = "employee"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/auth/v1/login", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        var user = json.RootElement.GetProperty("user");
        Assert.Equal("employee", user.GetProperty("user_type").GetString());
    }

    [Fact]
    public async Task POST_V1_Auth_Login_InvalidCredentials_Returns401()
    {
        await CleanDatabaseAsync();
        // Arrange
        var request = new
        {
            username = "invalid@example.com",
            password = "WrongPassword",
            user_type = "customer"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/auth/v1/login", request);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.NotNull(json.RootElement.GetProperty("error").GetString());
        Assert.NotEmpty(json.RootElement.GetProperty("error").GetString()!);
        Assert.NotNull(json.RootElement.GetProperty("error_description").GetString());
        Assert.NotEmpty(json.RootElement.GetProperty("error_description").GetString()!);
    }


    [Fact]
    public async Task POST_V1_Auth_Login_AccountLocked_Returns423WithLockedUntil()
    {
        await CleanDatabaseAsync();
        // Arrange - Simulate account lockout by making 5 failed attempts first
        var failedRequest = new
        {
            username = "locked@example.com",
            password = "WrongPassword",
            user_type = "customer"
        };

        // Make 5 failed attempts to trigger lockout
        for (int i = 0; i < 5; i++)
        {
            await Client.PostAsJsonAsync("/auth/v1/login", failedRequest);
        }

        // Act - 6th attempt should return 423
        var response = await Client.PostAsJsonAsync("/auth/v1/login", failedRequest);

        // Assert
        Assert.Equal(HttpStatusCode.Locked, response.StatusCode); // 423

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.NotNull(json.RootElement.GetProperty("locked_until").GetString());
        Assert.NotEmpty(json.RootElement.GetProperty("locked_until").GetString()!);
        Assert.Contains("locked", json.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task POST_V1_Auth_Login_RateLimitExceeded_Returns429WithRetryAfter()
    {
        await CleanDatabaseAsync();
        // Arrange - Make 20+ failed requests from same IP to trigger rate limit
        // Use different usernames to avoid account lockout (5 attempts per user)
        // but same IP to trigger IP-based rate limiting (20 attempts per IP)

        // Act - Make 21 failed requests with different usernames to exceed IP rate limit (20/15min)
        HttpResponseMessage? response = null;
        for (int i = 0; i < 21; i++)
        {
            var request = new
            {
                username = $"ratelimit{i}@example.com",  // Different username each time
                password = "WrongPassword123!",  // Invalid password to trigger failed attempts
                user_type = "employee"  // Use employee to avoid interference with customer account lockout tests
            };
            response = await Client.PostAsJsonAsync("/auth/v1/login", request);
        }

        // Assert - 21st request should be rate limited
        Assert.Equal(HttpStatusCode.TooManyRequests, response!.StatusCode); // 429
        Assert.True(response.Headers.Contains("Retry-After"));
    }

    [Fact]
    public async Task POST_V1_Auth_Login_WithIAMEnabled_ReturnsJWTWithPermissions()
    {
        await CleanDatabaseAsync();
        // Arrange
        // Use WithWebHostBuilder to override configuration for this specific test
        using var customFactory = Factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((context, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Features:IAMIntegrationEnabled"] = "true",
                    ["IAM:BaseUrl"] = "http://localhost:5100"
                });
            });
        });

        var client = customFactory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Client-IP", "127.0.0.1");

        var request = new
        {
            username = "customer@example.com",
            password = "ValidPassword123!",
            user_type = "customer"
        };

        // Act
        var response = await client.PostAsJsonAsync("/auth/v1/login", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);
        var accessToken = json.RootElement.GetProperty("access_token").GetString();

        Assert.NotNull(accessToken);

        // Decode JWT to check for permissions and roles claims
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(accessToken);

        var permissionClaims = token.Claims.Where(c => c.Type == "permissions").Select(c => c.Value).ToList();
        var roleClaims = token.Claims.Where(c => c.Type == "roles").Select(c => c.Value).ToList();

        Assert.Contains("auth.api_keys.manage", permissionClaims);
        Assert.Contains("auth.users.read", permissionClaims);
        Assert.Contains("security_admin", roleClaims);
    }

    [Fact]
    public async Task POST_V1_Auth_Login_IAMServiceDown_ReturnsJWTWithEmptyPermissions()
    {
        await CleanDatabaseAsync();
        // Arrange
        using var customFactory = Factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((context, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Features:IAMIntegrationEnabled"] = "true",
                    ["IAM:BaseUrl"] = "http://localhost:5101" // Wrong port to simulate failure
                });
            });
        });

        var client = customFactory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Client-IP", "127.0.0.1");

        var request = new
        {
            username = "customer@example.com",
            password = "ValidPassword123!",
            user_type = "customer"
        };

        // Act
        var response = await client.PostAsJsonAsync("/auth/v1/login", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);
        var accessToken = json.RootElement.GetProperty("access_token").GetString();

        Assert.NotNull(accessToken);

        // Decode JWT to check for empty permissions
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(accessToken);

        var permissionClaims = token.Claims.Where(c => c.Type == "permissions").ToList();
        var roleClaims = token.Claims.Where(c => c.Type == "roles").ToList();

        Assert.Empty(permissionClaims);
        Assert.Empty(roleClaims);
    }
}
