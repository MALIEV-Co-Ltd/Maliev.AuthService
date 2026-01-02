using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Maliev.AuthService.Tests.Infrastructure;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

[Collection("AuthService Collection")]
public class ServiceLoginContractTests : IntegrationTestBase
{
    public ServiceLoginContractTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_ValidCredentials_Returns200WithServiceToken()
    {
        await CleanDatabaseAsync();
        // Arrange
        var request = new
        {
            client_id = "service-dev-customer-api",
            client_secret = TestConstants.DummyValidServiceSecret
        };

        // Act
        var response = await Client.PostAsJsonAsync("/auth/v1/service/login", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.NotNull(json.RootElement.GetProperty("access_token").GetString());
        Assert.NotEmpty(json.RootElement.GetProperty("access_token").GetString()!);
        Assert.Equal("Bearer", json.RootElement.GetProperty("token_type").GetString());
        Assert.True(json.RootElement.GetProperty("expires_in").GetInt32() > 0);

        // Service tokens should not have refresh tokens
        Assert.False(json.RootElement.TryGetProperty("refresh_token", out _));
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_InvalidClientId_Returns401()
    {
        await CleanDatabaseAsync();
        // Arrange - Use properly formatted but non-existent client ID
        var request = new
        {
            client_id = "service-dev-nonexistent",
            client_secret = TestConstants.DummySecret
        };

        // Act
        var response = await Client.PostAsJsonAsync("/auth/v1/service/login", request);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.NotNull(json.RootElement.GetProperty("error").GetString());
        Assert.NotEmpty(json.RootElement.GetProperty("error").GetString()!);
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_InvalidClientSecret_Returns401()
    {
        await CleanDatabaseAsync();
        // Arrange
        var request = new
        {
            client_id = "service-dev-customer-api",
            client_secret = TestConstants.DummyWrongSecret
        };

        // Act
        var response = await Client.PostAsJsonAsync("/auth/v1/service/login", request);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
