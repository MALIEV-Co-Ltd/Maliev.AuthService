using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Maliev.AuthService.Api.Models.Request;
using Maliev.AuthService.Api.Models.Response;
using Maliev.AuthService.Tests.Infrastructure;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

[Collection("AuthService Collection")]
public class GoogleExchangeContractTests : IntegrationTestBase
{
    public GoogleExchangeContractTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task ExchangeGoogleToken_WithExistingEmployee_ShouldReturnTokens()
    {
        await CleanDatabaseAsync();
        // Arrange
        var request = new
        {
            email = "existing.employee@maliev.com",
            full_name = "Existing Employee"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/auth/v1/exchange/google", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.NotNull(json.RootElement.GetProperty("access_token").GetString());
        Assert.NotNull(json.RootElement.GetProperty("refresh_token").GetString());

        var user = json.RootElement.GetProperty("user");
        Assert.Equal("employee", user.GetProperty("user_type").GetString());
        Assert.Equal("existing.employee@maliev.com", user.GetProperty("email").GetString());
    }

    [Fact]
    public async Task ExchangeGoogleToken_WithNewEmployee_ShouldAutoProvisionAndReturnTokens()
    {
        await CleanDatabaseAsync();
        // Arrange
        var request = new
        {
            email = "new.employee@maliev.com",
            full_name = "New Employee"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/auth/v1/exchange/google", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.NotNull(json.RootElement.GetProperty("access_token").GetString());

        var user = json.RootElement.GetProperty("user");
        Assert.Equal("employee", user.GetProperty("user_type").GetString());
        Assert.Equal("new.employee@maliev.com", user.GetProperty("email").GetString());
    }

    [Fact]
    public async Task ExchangeGoogleToken_WithInvalidDomain_ShouldReturnForbidden()
    {
        await CleanDatabaseAsync();
        // Arrange
        var request = new
        {
            email = "user@gmail.com",
            full_name = "Gmail User"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/auth/v1/exchange/google", request);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<ErrorResponse>();
        Assert.Equal("invalid_domain", result?.Error);
    }

    [Fact]
    public async Task ExchangeGoogleToken_WithTerminatedEmployee_ShouldReturnForbidden()
    {
        await CleanDatabaseAsync();
        // Arrange
        var request = new
        {
            email = "terminated.employee@maliev.com",
            full_name = "Terminated Employee"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/auth/v1/exchange/google", request);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<ErrorResponse>();
        Assert.Equal("inactive_account", result?.Error);
    }
}
