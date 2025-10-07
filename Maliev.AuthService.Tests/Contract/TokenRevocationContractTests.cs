using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Maliev.AuthService.Tests.Contract;

[TestClass]
public class TokenRevocationContractTests
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
    public async Task POST_V1_Auth_Revoke_ValidToken_Returns204()
    {
        // Arrange - Get real tokens from login
        var (accessToken, _) = await GetValidTokensAsync();
        var request = new
        {
            token = accessToken,
            reason = "user_logout"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/v1/revoke", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.NoContent);
    }

    [TestMethod]
    public async Task POST_V1_Auth_Revoke_AlreadyRevokedToken_Returns204Idempotent()
    {
        // Arrange - Get real tokens from login
        var (accessToken, _) = await GetValidTokensAsync();
        var request = new
        {
            token = accessToken,
            reason = "user_logout"
        };

        // Act - First revocation
        var firstResponse = await _client.PostAsJsonAsync("/auth/v1/revoke", request);
        firstResponse.StatusCode.Should().Be(HttpStatusCode.NoContent);

        // Act - Second revocation (idempotent)
        var response = await _client.PostAsJsonAsync("/auth/v1/revoke", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.NoContent);
    }

    [TestMethod]
    public async Task POST_V1_Auth_Revoke_MissingToken_Returns400()
    {
        // Arrange
        var request = new
        {
            reason = "user_logout"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/v1/revoke", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }
}
