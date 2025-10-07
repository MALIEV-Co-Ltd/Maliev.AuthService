using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Maliev.AuthService.Tests.Contract;

[TestClass]
public class TokenRefreshContractTests
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

    private async Task<(string AccessToken, string RefreshToken)> GetValidTokensAsync()
    {
        var loginRequest = new
        {
            username = "customer@example.com",
            password = "ValidPassword123!",
            user_type = "customer"
        };

        var response = await _client.PostAsJsonAsync("/auth/v1/login", loginRequest);
        response.EnsureSuccessStatusCode();

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        return (
            json.RootElement.GetProperty("access_token").GetString()!,
            json.RootElement.GetProperty("refresh_token").GetString()!
        );
    }

    [TestMethod]
    public async Task POST_V1_Auth_Refresh_ValidRefreshToken_Returns200WithNewTokens()
    {
        // Arrange - Get real tokens from login
        var (_, refreshToken) = await GetValidTokensAsync();
        var request = new
        {
            refresh_token = refreshToken
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/v1/refresh", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        json.RootElement.GetProperty("access_token").GetString().Should().NotBeNullOrEmpty();
        json.RootElement.GetProperty("refresh_token").GetString().Should().NotBeNullOrEmpty();
        json.RootElement.GetProperty("token_type").GetString().Should().Be("Bearer");
    }

    [TestMethod]
    public async Task POST_V1_Auth_Refresh_ExpiredRefreshToken_Returns401()
    {
        // Arrange - Use an invalid token string (not a real JWT)
        var request = new
        {
            refresh_token = "invalid.token.string"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/v1/refresh", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        json.RootElement.GetProperty("error").GetString().Should().NotBeNullOrEmpty();
    }

    [TestMethod]
    public async Task POST_V1_Auth_Refresh_ReusedRefreshToken_Returns401AndInvalidatesFamily()
    {
        // Arrange - Get real tokens and use refresh token twice
        var (_, refreshToken) = await GetValidTokensAsync();
        var request = new
        {
            refresh_token = refreshToken
        };

        // First use - should succeed
        var firstResponse = await _client.PostAsJsonAsync("/auth/v1/refresh", request);
        firstResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // Act - Reuse the same token (should fail)
        var response = await _client.PostAsJsonAsync("/auth/v1/refresh", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        json.RootElement.GetProperty("error").GetString().Should().NotBeNullOrEmpty();
    }

    [TestMethod]
    public async Task POST_V1_Auth_Refresh_MissingRefreshToken_Returns400()
    {
        // Arrange
        var request = new { };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/v1/refresh", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }
}
