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
        var result = await response.Content.ReadFromJsonAsync<LoginResponse>(JsonOptions);

        Assert.NotNull(result?.AccessToken);
        Assert.NotNull(result?.RefreshToken);

        Assert.Equal("employee", result?.User.UserType);
        Assert.Equal("existing.employee@maliev.com", result?.User.Email);
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
        var result = await response.Content.ReadFromJsonAsync<LoginResponse>(JsonOptions);

        Assert.NotNull(result?.AccessToken);

        Assert.Equal("employee", result?.User.UserType);
        Assert.Equal("new.employee@maliev.com", result?.User.Email);
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
        var result = await response.Content.ReadFromJsonAsync<ErrorResponse>(JsonOptions);
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
        var result = await response.Content.ReadFromJsonAsync<ErrorResponse>(JsonOptions);
        Assert.Equal("inactive_account", result?.Error);
    }

    [Fact]
    public async Task ExchangeGoogleToken_WithServiceUnavailable_ShouldReturn503()
    {
        await CleanDatabaseAsync();
        // Arrange
        var request = new
        {
            email = "service.down@maliev.com",
            full_name = "Service Down"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/auth/v1/exchange/google", request);

        // Assert
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<ErrorResponse>(JsonOptions);
        Assert.Equal("service_unavailable", result?.Error);
    }

    [Fact]
    public async Task ExchangeGoogleToken_WithProvisionFailed_ShouldReturn403()
    {
        await CleanDatabaseAsync();
        // Arrange
        var request = new
        {
            email = "provision.fail@maliev.com",
            full_name = "Provision Fail"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/auth/v1/exchange/google", request);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<ErrorResponse>(JsonOptions);
        Assert.Equal("provision_failed", result?.Error);
    }
}
