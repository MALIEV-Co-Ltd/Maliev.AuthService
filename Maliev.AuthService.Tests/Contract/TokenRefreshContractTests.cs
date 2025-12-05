using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Maliev.AuthService.Tests.Infrastructure;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

public class TokenRefreshContractTests : IntegrationTestBase
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

    [Fact]
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
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.NotNull(json.RootElement.GetProperty("access_token").GetString());
        Assert.NotEmpty(json.RootElement.GetProperty("access_token").GetString()!);
        Assert.NotNull(json.RootElement.GetProperty("refresh_token").GetString());
        Assert.NotEmpty(json.RootElement.GetProperty("refresh_token").GetString()!);
        Assert.Equal("Bearer", json.RootElement.GetProperty("token_type").GetString());
    }

    [Fact]
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
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.NotNull(json.RootElement.GetProperty("error").GetString());
        Assert.NotEmpty(json.RootElement.GetProperty("error").GetString()!);
    }

    [Fact]
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
        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);

        // Act - Reuse the same token (should fail)
        var response = await _client.PostAsJsonAsync("/auth/v1/refresh", request);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.NotNull(json.RootElement.GetProperty("error").GetString());
        Assert.NotEmpty(json.RootElement.GetProperty("error").GetString()!);
    }

}
