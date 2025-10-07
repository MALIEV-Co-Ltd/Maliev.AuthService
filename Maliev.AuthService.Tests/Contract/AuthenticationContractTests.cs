using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Maliev.AuthService.Tests.Contract;

[TestClass]
public class AuthenticationContractTests
{
    private HttpClient _client = null!;
    private TestWebApplicationFactory _factory = null!;

    [TestInitialize]
    public void Setup()
    {
        _factory = new TestWebApplicationFactory();
        _client = _factory.CreateClient();
    }

    [TestCleanup]
    public void Cleanup()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    [TestMethod]
    public async Task POST_V1_Auth_Login_ValidCustomerCredentials_Returns200WithTokens()
    {
        // Arrange
        var request = new
        {
            username = "customer@example.com",
            password = "ValidPassword123!",
            user_type = "customer"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/v1/login", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        json.RootElement.GetProperty("access_token").GetString().Should().NotBeNullOrEmpty();
        json.RootElement.GetProperty("refresh_token").GetString().Should().NotBeNullOrEmpty();
        json.RootElement.GetProperty("token_type").GetString().Should().Be("Bearer");
        json.RootElement.GetProperty("expires_in").GetInt32().Should().Be(900); // 15 minutes

        var user = json.RootElement.GetProperty("user");
        user.GetProperty("user_id").GetString().Should().NotBeNullOrEmpty();
        user.GetProperty("user_type").GetString().Should().Be("customer");
    }

    [TestMethod]
    public async Task POST_V1_Auth_Login_ValidEmployeeCredentials_Returns200WithCorrectUserType()
    {
        // Arrange
        var request = new
        {
            username = "employee@maliev.com",
            password = "ValidPassword123!",
            user_type = "employee"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/v1/login", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        var user = json.RootElement.GetProperty("user");
        user.GetProperty("user_type").GetString().Should().Be("employee");
    }

    [TestMethod]
    public async Task POST_V1_Auth_Login_InvalidCredentials_Returns401()
    {
        // Arrange
        var request = new
        {
            username = "invalid@example.com",
            password = "WrongPassword",
            user_type = "customer"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/v1/login", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        json.RootElement.GetProperty("error").GetString().Should().NotBeNullOrEmpty();
        json.RootElement.GetProperty("error_description").GetString().Should().NotBeNullOrEmpty();
    }

    [TestMethod]
    public async Task POST_V1_Auth_Login_MissingRequiredFields_Returns400WithValidationErrors()
    {
        // Arrange
        var request = new
        {
            username = "test@example.com"
            // Missing password and user_type
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/v1/login", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        json.RootElement.GetProperty("errors").EnumerateArray().Should().NotBeEmpty();
    }

    [TestMethod]
    public async Task POST_V1_Auth_Login_AccountLocked_Returns423WithLockedUntil()
    {
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
            await _client.PostAsJsonAsync("/auth/v1/login", failedRequest);
        }

        // Act - 6th attempt should return 423
        var response = await _client.PostAsJsonAsync("/auth/v1/login", failedRequest);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Locked); // 423

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        json.RootElement.GetProperty("locked_until").GetString().Should().NotBeNullOrEmpty();
        json.RootElement.GetProperty("error").GetString().Should().Contain("locked");
    }

    [TestMethod]
    public async Task POST_V1_Auth_Login_RateLimitExceeded_Returns429WithRetryAfter()
    {
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
                user_type = "customer"
            };
            response = await _client.PostAsJsonAsync("/auth/v1/login", request);
        }

        // Assert - 21st request should be rate limited
        response!.StatusCode.Should().Be(HttpStatusCode.TooManyRequests); // 429
        response.Headers.Should().ContainKey("Retry-After");
    }
}
