using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Maliev.AuthService.Tests.Infrastructure;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

[Collection("AuthService Collection")]
public class TokenRefreshAdditionalContractTests : IntegrationTestBase
{
    public TokenRefreshAdditionalContractTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    private async Task<(string AccessToken, string RefreshToken)> GetValidTokensAsync()
    {
        var loginRequest = new
        {
            username = "customer@example.com",
            password = TestConstants.DummyPassword,
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
    public async Task POST_V1_Auth_Refresh_MissingRefreshToken_Returns400()
    {
        await CleanDatabaseAsync();

        var response = await Client.PostAsJsonAsync("/auth/v1/refresh", new object());

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task POST_V1_Auth_Refresh_AfterLogout_Returns401()
    {
        await CleanDatabaseAsync();
        var (_, refreshToken) = await GetValidTokensAsync();

        var logoutRequest = new { refresh_token = refreshToken };
        await Client.PostAsJsonAsync("/auth/v1/logout", logoutRequest);

        var refreshRequest = new { refresh_token = refreshToken };
        var response = await Client.PostAsJsonAsync("/auth/v1/refresh", refreshRequest);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task POST_V1_Auth_Refresh_MultipleRefreshes_GeneratesUniqueTokens()
    {
        await CleanDatabaseAsync();
        var (_, refreshToken) = await GetValidTokensAsync();

        var accessTokens = new HashSet<string>();

        for (int i = 0; i < 3; i++)
        {
            var refreshRequest = new { refresh_token = refreshToken };
            var response = await Client.PostAsJsonAsync("/auth/v1/refresh", refreshRequest);
            var content = await response.Content.ReadAsStringAsync();
            var json = JsonDocument.Parse(content);

            var newRefreshToken = json.RootElement.GetProperty("refresh_token").GetString()!;
            refreshToken = newRefreshToken;

            var accessToken = json.RootElement.GetProperty("access_token").GetString()!;
            accessTokens.Add(accessToken);
        }

        Assert.Equal(3, accessTokens.Count);
    }

    [Fact]
    public async Task POST_V1_Auth_Refresh_ValidToken_ReturnsCorrectTokenType()
    {
        await CleanDatabaseAsync();
        var (_, refreshToken) = await GetValidTokensAsync();

        var request = new { refresh_token = refreshToken };
        var response = await Client.PostAsJsonAsync("/auth/v1/refresh", request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.Equal("Bearer", json.RootElement.GetProperty("token_type").GetString());
        Assert.Equal(900, json.RootElement.GetProperty("expires_in").GetInt32());
    }
}
