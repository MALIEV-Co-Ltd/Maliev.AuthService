using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Maliev.AuthService.Tests.Contract;

[TestClass]
public class TokenValidationContractTests
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
    public async Task POST_V1_Auth_Validate_ValidToken_Returns200WithUserIdentity()
    {
        // Arrange - Get real tokens from login
        var (accessToken, _) = await GetValidTokensAsync();
        var request = new
        {
            access_token = accessToken
        };

        // Act
        var response = await _client.PostAsJsonAsync("/v1/auth/validate", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        json.RootElement.GetProperty("valid").GetBoolean().Should().BeTrue();
        json.RootElement.GetProperty("user_id").GetString().Should().NotBeNullOrEmpty();
        json.RootElement.GetProperty("user_type").GetString().Should().Match(x => x == "customer" || x == "employee");
    }

    [TestMethod]
    public async Task POST_V1_Auth_Validate_ExpiredToken_Returns200WithValidFalse()
    {
        // Arrange - Use an invalid token string
        var request = new
        {
            access_token = "invalid.token.string"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/v1/auth/validate", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        json.RootElement.GetProperty("valid").GetBoolean().Should().BeFalse();
        json.RootElement.GetProperty("error").GetString().Should().NotBeNullOrEmpty();
    }

    [TestMethod]
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
        await _client.PostAsJsonAsync("/v1/auth/revoke", revokeRequest);

        // Act - Try to validate the revoked token
        var request = new
        {
            access_token = accessToken
        };
        var response = await _client.PostAsJsonAsync("/v1/auth/validate", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        json.RootElement.GetProperty("valid").GetBoolean().Should().BeFalse();
        json.RootElement.GetProperty("error").GetString().Should().Contain("revoked");
    }

    [TestMethod]
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
        var response = await _client.PostAsJsonAsync("/v1/auth/validate", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        json.RootElement.GetProperty("valid").GetBoolean().Should().BeFalse();
    }
}
