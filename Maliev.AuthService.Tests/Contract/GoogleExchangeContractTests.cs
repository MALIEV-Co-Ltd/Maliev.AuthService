using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Maliev.AuthService.Api.Authorization;
using Maliev.AuthService.Application.DTOs.Response;
using Maliev.AuthService.Tests.Infrastructure;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

[Collection("AuthService Collection")]
public class GoogleExchangeContractTests : IntegrationTestBase
{
    private const string EmployeeExchangePath = "/auth/v1/exchange/google";
    private const string EmployeeNoncePath = "/auth/v1/exchange/google/nonce";
    private const string CustomerExchangePath = "/auth/v1/exchange/google/customer";
    private const string CustomerNoncePath = "/auth/v1/exchange/google/customer/nonce";
    private const string ModelValidDummyNonce = "12345678901234567890123456789012";

    public GoogleExchangeContractTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task ExchangeGoogleToken_WithExistingEmployee_ShouldReturnTokens()
    {
        await CleanDatabaseAsync();
        using var client = CreateExchangeClient("IntranetBff");
        var nonce = await IssueNonceAsync(client, EmployeeNoncePath, "intranet");

        var response = await client.PostAsJsonAsync(EmployeeExchangePath, new
        {
            credential = "existing.employee@maliev.com",
            application = "intranet",
            nonce
        });

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
        using var client = CreateExchangeClient("IntranetBff");
        var nonce = await IssueNonceAsync(client, EmployeeNoncePath, "intranet");

        var response = await client.PostAsJsonAsync(EmployeeExchangePath, new
        {
            credential = "new.employee@maliev.com",
            application = "intranet",
            nonce
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<LoginResponse>(JsonOptions);
        Assert.NotNull(result?.AccessToken);
        Assert.Equal("employee", result?.User.UserType);
        Assert.Equal("new.employee@maliev.com", result?.User.Email);
    }

    [Theory]
    [InlineData("user@gmail.com", HttpStatusCode.Forbidden, "invalid_domain")]
    [InlineData("terminated.employee@maliev.com", HttpStatusCode.Forbidden, "inactive_account")]
    [InlineData("service.down@maliev.com", HttpStatusCode.ServiceUnavailable, "service_unavailable")]
    [InlineData("provision.fail@maliev.com", HttpStatusCode.Forbidden, "provision_failed")]
    public async Task ExchangeGoogleToken_EmployeeFailures_ReturnStableErrors(
        string credential,
        HttpStatusCode expectedStatus,
        string expectedError)
    {
        await CleanDatabaseAsync();
        using var client = CreateExchangeClient("IntranetBff");
        var nonce = await IssueNonceAsync(client, EmployeeNoncePath, "intranet");

        var response = await client.PostAsJsonAsync(EmployeeExchangePath, new
        {
            credential,
            application = "intranet",
            nonce
        });

        Assert.Equal(expectedStatus, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<ErrorResponse>(JsonOptions);
        Assert.Equal(expectedError, result?.Error);
    }

    [Fact]
    public async Task ExchangeGoogleToken_ReplayedNonce_IsRejected()
    {
        await CleanDatabaseAsync();
        using var client = CreateExchangeClient("IntranetBff");
        var nonce = await IssueNonceAsync(client, EmployeeNoncePath, "intranet");
        var request = new
        {
            credential = "existing.employee@maliev.com",
            application = "intranet",
            nonce
        };

        var first = await client.PostAsJsonAsync(EmployeeExchangePath, request);
        var replay = await client.PostAsJsonAsync(EmployeeExchangePath, request);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task EmployeeExchange_QuoteEngineCallerCannotUseIntranetApplication()
    {
        await CleanDatabaseAsync();
        using var client = CreateExchangeClient("QuoteEngineBff");

        var nonceResponse = await client.PostAsJsonAsync(EmployeeNoncePath, new { application = "intranet" });
        var exchangeResponse = await client.PostAsJsonAsync(EmployeeExchangePath, new
        {
            credential = "existing.employee@maliev.com",
            application = "intranet",
            nonce = ModelValidDummyNonce
        });

        Assert.Equal(HttpStatusCode.Forbidden, nonceResponse.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, exchangeResponse.StatusCode);
    }

    [Fact]
    public async Task CustomerExchange_CallerMustMatchApplicationBinding()
    {
        await CleanDatabaseAsync();
        using var quoteEngineClient = CreateExchangeClient("QuoteEngineBff");
        using var webClient = CreateExchangeClient("WebBff");

        var wrongQuoteEngineBinding = await quoteEngineClient.PostAsJsonAsync(
            CustomerNoncePath,
            new { application = "web" });
        var wrongWebBinding = await webClient.PostAsJsonAsync(
            CustomerNoncePath,
            new { application = "quote-engine" });
        var quoteEngineNonce = await IssueNonceAsync(
            quoteEngineClient,
            CustomerNoncePath,
            "quote-engine");
        var validQuoteEngineExchange = await quoteEngineClient.PostAsJsonAsync(CustomerExchangePath, new
        {
            credential = "customer@gmail.com",
            application = "quote-engine",
            nonce = quoteEngineNonce
        });

        Assert.Equal(HttpStatusCode.Forbidden, wrongQuoteEngineBinding.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, wrongWebBinding.StatusCode);
        Assert.Equal(HttpStatusCode.OK, validQuoteEngineExchange.StatusCode);
    }

    [Fact]
    public async Task ExchangeGoogleToken_WithoutServiceAuthentication_ReturnsUnauthorized()
    {
        await CleanDatabaseAsync();
        using var anonymousClient = Factory.CreateClient();

        var response = await anonymousClient.PostAsJsonAsync(EmployeeExchangePath, new
        {
            credential = "existing.employee@maliev.com",
            application = "intranet",
            nonce = ModelValidDummyNonce
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ExchangeGoogleToken_WithoutExchangePermission_ReturnsForbidden()
    {
        await CleanDatabaseAsync();

        var response = await Client.PostAsJsonAsync(EmployeeExchangePath, new
        {
            credential = "existing.employee@maliev.com",
            application = "intranet",
            nonce = ModelValidDummyNonce
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
        using var client = CreateExchangeClient("WebBff");
        var nonce = await IssueNonceAsync(client, CustomerNoncePath, "web");

        var response = await client.PostAsJsonAsync(CustomerExchangePath, new
        {
            credential = "customer@gmail.com",
            application = "web",
            nonce
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<LoginResponse>(JsonOptions);
        Assert.NotNull(result?.AccessToken);
        Assert.NotNull(result?.RefreshToken);
        Assert.Equal("customer", result?.User.UserType);
        Assert.Equal("customer@gmail.com", result?.User.Email);

        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(result!.AccessToken);
        Assert.NotNull(token.Claims.FirstOrDefault(claim => claim.Type == "customer_id"));
        Assert.Equal(token.Subject, token.Claims.First(claim => claim.Type == "principal_id").Value);
    }

    [Fact]
    public async Task ExchangeGoogleToken_WithCallerAssertedIdentityFields_ReturnsBadRequest()
    {
        await CleanDatabaseAsync();
        using var client = CreateExchangeClient("IntranetBff");
        var nonce = await IssueNonceAsync(client, EmployeeNoncePath, "intranet");

        var response = await client.PostAsJsonAsync(EmployeeExchangePath, new
        {
            credential = "existing.employee@maliev.com",
            application = "intranet",
            nonce,
            email = "attacker@maliev.com",
            google_user_id = "attacker-sub"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task ExchangeGoogleToken_FromUnapprovedService_ReturnsForbidden()
    {
        await CleanDatabaseAsync();
        using var client = CreateExchangeClient("UnrelatedService");

        var response = await client.PostAsJsonAsync(EmployeeExchangePath, new
        {
            credential = "existing.employee@maliev.com",
            application = "intranet",
            nonce = ModelValidDummyNonce
        });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    private async Task<string> IssueNonceAsync(HttpClient client, string path, string application)
    {
        var response = await client.PostAsJsonAsync(path, new { application });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<GoogleIdentityNonceResponse>(JsonOptions);
        Assert.NotNull(result);
        Assert.True(result.ExpiresAtUtc > DateTime.UtcNow);
        Assert.True(result.Nonce.Length >= 32);
        return result.Nonce;
    }

    private HttpClient CreateExchangeClient(string serviceName)
    {
        var token = Factory.CreateTestJwtToken(
            Guid.NewGuid().ToString(),
            ["service"],
            new Dictionary<string, string>
            {
                ["permission"] = AuthPermissions.ExchangeIdentities,
                ["user_type"] = "service",
                ["service_name"] = serviceName
            });
        var client = Factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        client.DefaultRequestHeaders.Add("X-Test-Client-IP", "127.0.0.1");
        return client;
    }
}
