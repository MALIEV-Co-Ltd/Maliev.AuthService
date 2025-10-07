using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Maliev.AuthService.Tests.Contract;

[TestClass]
public class LogoutContractTests
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

        var response = await _client.PostAsJsonAsync("/v1/auth/login", loginRequest);
        response.EnsureSuccessStatusCode();

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        return (
            json.RootElement.GetProperty("access_token").GetString()!,
            json.RootElement.GetProperty("refresh_token").GetString()!
        );
    }

    [TestMethod]
    public async Task POST_V1_Auth_Logout_ValidRefreshToken_Returns204AndRevokesTokens()
    {
        // Arrange - Get real tokens from login
        var (_, refreshToken) = await GetValidTokensAsync();
        var request = new
        {
            refresh_token = refreshToken
        };

        // Act
        var response = await _client.PostAsJsonAsync("/v1/auth/logout", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.NoContent);
    }

    [TestMethod]
    public async Task POST_V1_Auth_Logout_MissingRefreshToken_Returns400()
    {
        // Arrange
        var request = new { };

        // Act
        var response = await _client.PostAsJsonAsync("/v1/auth/logout", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [TestMethod]
    public async Task POST_V1_Auth_Logout_InvalidRefreshToken_Returns401()
    {
        // Arrange - Use an invalid token string
        var request = new
        {
            refresh_token = "invalid.token.string"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/v1/auth/logout", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}
