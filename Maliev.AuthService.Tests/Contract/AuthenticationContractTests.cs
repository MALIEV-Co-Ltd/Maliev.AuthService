using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

/// <summary>
/// Contract tests for POST /auth/login endpoint.
/// These tests verify the API contract matches the OpenAPI specification.
/// </summary>
[Trait("Category", "Contract")]
public class AuthenticationContractTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public AuthenticationContractTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Login_WithValidCredentials_ReturnsLoginResponse()
    {
        // Arrange
        var request = new
        {
            username = "test.customer@example.com",
            password = "Password123!",
            user_type = "customer"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/login", request);

        // Assert - This should FAIL until endpoint is implemented
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadFromJsonAsync<LoginResponse>();
        content.Should().NotBeNull();
        content!.AccessToken.Should().NotBeNullOrEmpty();
        content.RefreshToken.Should().NotBeNullOrEmpty();
        content.TokenType.Should().Be("Bearer");
        content.ExpiresIn.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task Login_WithInvalidCredentials_Returns401()
    {
        // Arrange
        var request = new
        {
            username = "invalid@example.com",
            password = "wrongpassword",
            user_type = "customer"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/login", request);

        // Assert - This should FAIL until endpoint is implemented
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        var content = await response.Content.ReadFromJsonAsync<ErrorResponse>();
        content.Should().NotBeNull();
        content!.Error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Login_ExceedingRateLimit_Returns429()
    {
        // Arrange
        var request = new
        {
            username = "test@example.com",
            password = "wrongpassword",
            user_type = "customer"
        };

        // Act - Attempt 6 failed logins (exceeds 5 attempt limit)
        HttpResponseMessage? lastResponse = null;
        for (int i = 0; i < 6; i++)
        {
            lastResponse = await _client.PostAsJsonAsync("/auth/login", request);
        }

        // Assert - This should FAIL until rate limiting is implemented
        lastResponse!.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
    }
}
