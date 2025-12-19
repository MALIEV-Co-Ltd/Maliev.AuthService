using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Maliev.AuthService.Tests.Infrastructure;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

[Collection("AuthService Collection")]
public class TokenRevocationContractTests : IntegrationTestBase
{
    public TokenRevocationContractTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    private async Task<(string AccessToken, string RefreshToken)> GetValidTokensAsync()
    {
        var loginRequest = new
        {
            username = "customer@example.com",
            password = "ValidPassword123!",
            user_type = "customer"
        };

        var response = await Client.PostAsJsonAsync("/auth/v1/login", loginRequest);
        response.EnsureSuccessStatusCode();

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        return (
            json.RootElement.GetProperty("access_token").GetString()!,
            json.RootElement.GetProperty("refresh_token").GetString()!
        );
    }

    [Fact]
    public async Task POST_V1_Auth_Revoke_ValidToken_Returns204()
    {
        await CleanDatabaseAsync();
        // Arrange - Get real tokens from login
        var (accessToken, _) = await GetValidTokensAsync();
        var request = new
        {
            token = accessToken,
            reason = "user_logout"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/auth/v1/revoke", request);

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Fact]
    public async Task POST_V1_Auth_Revoke_AlreadyRevokedToken_Returns204Idempotent()
    {
        await CleanDatabaseAsync();
        // Arrange - Get real tokens from login
        var (accessToken, _) = await GetValidTokensAsync();
        var request = new
        {
            token = accessToken,
            reason = "user_logout"
        };

        // Act - First revocation
        var firstResponse = await Client.PostAsJsonAsync("/auth/v1/revoke", request);
        Assert.Equal(HttpStatusCode.NoContent, firstResponse.StatusCode);

        // Act - Second revocation (idempotent)
        var response = await Client.PostAsJsonAsync("/auth/v1/revoke", request);

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

}
