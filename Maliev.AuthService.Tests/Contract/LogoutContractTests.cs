using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

using Maliev.AuthService.Tests.Infrastructure;

namespace Maliev.AuthService.Tests.Contract;

[TestClass]
public class LogoutContractTests : IntegrationTestBase
{

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
    public async Task POST_V1_Auth_Logout_ValidRefreshToken_Returns204AndRevokesTokens()
    {
        // Arrange - Get real tokens from login
        var (_, refreshToken) = await GetValidTokensAsync();
        var request = new
        {
            refresh_token = refreshToken
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/v1/logout", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.NoContent);
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
        var response = await _client.PostAsJsonAsync("/auth/v1/logout", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}
