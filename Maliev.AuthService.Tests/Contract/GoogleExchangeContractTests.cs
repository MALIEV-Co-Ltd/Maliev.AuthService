using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Maliev.AuthService.Api.Authorization;
using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Application.DTOs.Response;
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
            credential = "existing.employee@maliev.com",
            application = "intranet"
        };
        using var exchangeClient = CreateExchangeClient();

        // Act
        var response = await exchangeClient.PostAsJsonAsync("/auth/v1/exchange/google", request);

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
            credential = "new.employee@maliev.com",
            application = "intranet"
        };
        using var exchangeClient = CreateExchangeClient();

        // Act
        var response = await exchangeClient.PostAsJsonAsync("/auth/v1/exchange/google", request);

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
            credential = "user@gmail.com",
            application = "intranet"
        };
        using var exchangeClient = CreateExchangeClient();

        // Act
        var response = await exchangeClient.PostAsJsonAsync("/auth/v1/exchange/google", request);

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
            credential = "terminated.employee@maliev.com",
            application = "intranet"
        };
        using var exchangeClient = CreateExchangeClient();

        // Act
        var response = await exchangeClient.PostAsJsonAsync("/auth/v1/exchange/google", request);

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
            credential = "service.down@maliev.com",
            application = "intranet"
        };
        using var exchangeClient = CreateExchangeClient();

        // Act
        var response = await exchangeClient.PostAsJsonAsync("/auth/v1/exchange/google", request);

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
            credential = "provision.fail@maliev.com",
            application = "intranet"
        };
        using var exchangeClient = CreateExchangeClient();

        // Act
        var response = await exchangeClient.PostAsJsonAsync("/auth/v1/exchange/google", request);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<ErrorResponse>(JsonOptions);
        Assert.Equal("provision_failed", result?.Error);
    }

    [Fact]
    public async Task ExchangeGoogleToken_WithoutServiceAuthentication_ReturnsUnauthorized()
    {
        await CleanDatabaseAsync();
        using var anonymousClient = Factory.CreateClient();

        var response = await anonymousClient.PostAsJsonAsync("/auth/v1/exchange/google", new
        {
            credential = "existing.employee@maliev.com",
            application = "intranet"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ExchangeGoogleToken_WithoutExchangePermission_ReturnsForbidden()
    {
        await CleanDatabaseAsync();

        var response = await Client.PostAsJsonAsync("/auth/v1/exchange/google", new
        {
            credential = "existing.employee@maliev.com",
            application = "intranet"
        });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Login_WithoutServiceAuthentication_RemainsPublic()
    {
        await CleanDatabaseAsync();
        using var anonymousClient = Factory.CreateClient();

        var response = await anonymousClient.PostAsJsonAsync("/auth/v1/login", new
        {
            username = "customer@example.com",
            password = TestConstants.DummyPassword,
            user_type = "customer"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task ExchangeCustomerGoogleToken_WithPublicGoogleAccount_ShouldReturnCustomerSession()
    {
        await CleanDatabaseAsync();
        // Arrange
        var request = new
        {
            credential = "customer@gmail.com",
            application = "web"
        };
        using var exchangeClient = CreateExchangeClient();

        // Act
        var response = await exchangeClient.PostAsJsonAsync("/auth/v1/exchange/google/customer", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<LoginResponse>(JsonOptions);

        Assert.NotNull(result?.AccessToken);
        Assert.NotNull(result?.RefreshToken);
        Assert.Equal("customer", result?.User.UserType);
        Assert.Equal("customer@gmail.com", result?.User.Email);

        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(result!.AccessToken);
        Assert.NotNull(token.Claims.FirstOrDefault(c => c.Type == "customer_id"));
        Assert.Equal(token.Subject, token.Claims.First(c => c.Type == "principal_id").Value);
    }

    [Fact]
    public async Task ExchangeGoogleToken_WithCallerAssertedIdentityFields_ReturnsBadRequest()
    {
        await CleanDatabaseAsync();
        using var exchangeClient = CreateExchangeClient();

        var response = await exchangeClient.PostAsJsonAsync("/auth/v1/exchange/google", new
        {
            credential = "existing.employee@maliev.com",
            application = "intranet",
            email = "attacker@maliev.com",
            google_user_id = "attacker-sub"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private HttpClient CreateExchangeClient()
    {
        var token = Factory.CreateTestJwtToken(
            Guid.NewGuid().ToString(),
            ["service"],
            new Dictionary<string, string>
            {
                ["permission"] = AuthPermissions.ExchangeIdentities,
                ["user_type"] = "service",
                ["service_name"] = "QuoteEngineBff"
            });
        var client = Factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        client.DefaultRequestHeaders.Add("X-Test-Client-IP", "127.0.0.1");
        return client;
    }

    [Fact]
    public async Task ExchangeGoogleToken_FromUnapprovedService_ReturnsForbidden()
    {
        await CleanDatabaseAsync();
        var token = Factory.CreateTestJwtToken(
            Guid.NewGuid().ToString(),
            ["service"],
            new Dictionary<string, string>
            {
                ["permission"] = AuthPermissions.ExchangeIdentities,
                ["user_type"] = "service",
                ["service_name"] = "UnrelatedService"
            });
        using var client = Factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.PostAsJsonAsync("/auth/v1/exchange/google", new
        {
            credential = "existing.employee@maliev.com",
            application = "intranet"
        });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
}
