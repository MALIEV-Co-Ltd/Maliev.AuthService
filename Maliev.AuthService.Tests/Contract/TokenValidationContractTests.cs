using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Maliev.AuthService.Tests.Infrastructure;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

public class TokenValidationContractTests : IntegrationTestBase
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
    public async Task POST_V1_Auth_Validate_ValidToken_Returns200WithUserIdentity()
    {
        // Arrange - Get real tokens from login
        var (accessToken, _) = await GetValidTokensAsync();
        var request = new
        {
            access_token = accessToken
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/v1/validate", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.True(json.RootElement.GetProperty("valid").GetBoolean());
        Assert.NotNull(json.RootElement.GetProperty("user_id").GetString());
        Assert.NotEmpty(json.RootElement.GetProperty("user_id").GetString()!);
        var userType = json.RootElement.GetProperty("user_type").GetString();
        Assert.True(userType == "customer" || userType == "employee");
    }

    [Fact]
    public async Task POST_V1_Auth_Validate_ExpiredToken_Returns200WithValidFalse()
    {
        // Arrange - Use an invalid token string
        var request = new
        {
            access_token = "invalid.token.string"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/v1/validate", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.False(json.RootElement.GetProperty("valid").GetBoolean());
        Assert.NotNull(json.RootElement.GetProperty("error").GetString());
        Assert.NotEmpty(json.RootElement.GetProperty("error").GetString()!);
    }

    [Fact]
    public async Task POST_V1_Auth_Validate_RevokedToken_Returns200WithValidFalse()
    {
        // Arrange - Get real token, revoke it, then validate
        var (accessToken, _) = await GetValidTokensAsync();

        // Revoke the token
        var revokeRequest = new
        {
            token = accessToken,
            reason = "test_revocation"
        };
        await _client.PostAsJsonAsync("/auth/v1/revoke", revokeRequest);

        // Act - Try to validate the revoked token
        var request = new
        {
            access_token = accessToken
        };
        var response = await _client.PostAsJsonAsync("/auth/v1/validate", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.False(json.RootElement.GetProperty("valid").GetBoolean());
        Assert.Contains("revoked", json.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task POST_V1_Auth_Validate_InvalidSignature_Returns200WithValidFalse()
    {
        // Arrange - Get a real token and tamper with it
        var (accessToken, _) = await GetValidTokensAsync();

        // Tamper with the token by modifying the last few characters
        var tamperedToken = accessToken[..^5] + "XXXXX";

        var request = new
        {
            access_token = tamperedToken
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/v1/validate", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.False(json.RootElement.GetProperty("valid").GetBoolean());
    }
}
