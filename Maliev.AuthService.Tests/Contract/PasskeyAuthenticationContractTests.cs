using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Maliev.AuthService.Api.Authorization;
using Maliev.AuthService.Application.DTOs.Response;
using Maliev.AuthService.Infrastructure.DbContexts;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

/// <summary>
/// HTTP contract tests for the service-authenticated, snake-case passkey ceremony boundary.
/// </summary>
public sealed class PasskeyAuthenticationContractTests : IClassFixture<TestWebApplicationFactory>
{
    private const string BeginPath = "/auth/v2/passkey/auth/begin";
    private const string CompletePath = "/auth/v2/passkey/auth/complete";
    private const string LegacyBeginPath = "/auth/v1/passkey/auth/begin";
    private const string LegacyCompletePath = "/auth/v1/passkey/auth/complete";
    private readonly TestWebApplicationFactory _rootFactory;
    private readonly WebApplicationFactory<Program> _factory;

    /// <summary>Initializes the contract host with passkey authentication enabled for tests.</summary>
    public PasskeyAuthenticationContractTests(TestWebApplicationFactory factory)
    {
        _rootFactory = factory;
        _factory = factory.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Passkey:Enabled"] = "true",
                    ["Passkey:RpId"] = "maliev.test",
                    ["Passkey:RpName"] = "MALIEV Test",
                    ["Passkey:AllowedOrigins:0"] = "https://app.maliev.test",
                    ["Passkey:AllowedOrigins:1"] = "https://www.maliev.test",
                    ["Passkey:AllowedOrigins:2"] = "https://make.maliev.test",
                    ["Passkey:Bindings:web:ServiceName"] = "WebBff",
                    ["Passkey:Bindings:web:PrincipalType"] = "Customer"
                })));
    }

    /// <summary>Verifies the trusted Web BFF receives an additive snake-case, discoverable flow.</summary>
    [Fact]
    public async Task BeginPasskeyAuthentication_WebBff_ReturnsSnakeCaseOneTimeOptions()
    {
        using var client = CreateServiceClient("WebBff");

        using var response = await client.PostAsJsonAsync(BeginPath, new { application = "web" });

        var responseBody = await response.Content.ReadAsStringAsync();
        Assert.True(
            response.StatusCode == HttpStatusCode.OK,
            $"Expected 200 OK but received {(int)response.StatusCode}: {responseBody}");
        var payload = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(43, payload.GetProperty("flow_id").GetString()?.Length);
        Assert.True(payload.GetProperty("expires_at_utc").GetDateTime() > DateTime.UtcNow);
        Assert.Equal("maliev.test", payload.GetProperty("rp_id").GetString());
        Assert.True(payload.GetProperty("challenge").GetString()?.Length >= 43);
        Assert.Equal(JsonValueKind.Array, payload.GetProperty("allow_credentials").ValueKind);
        Assert.Equal(0, payload.GetProperty("allow_credentials").GetArrayLength());
        Assert.Equal("required", payload.GetProperty("user_verification").GetString());
        Assert.Equal((ulong)300_000, payload.GetProperty("timeout").GetUInt64());
        Assert.False(payload.TryGetProperty("principal_id", out _));
        Assert.False(payload.TryGetProperty("flowId", out _));
    }

    /// <summary>Verifies an enabled host rejects an unbounded or disabled outstanding-ceremony quota.</summary>
    [Fact]
    public void PasskeyAuthentication_ZeroOutstandingQuota_RejectsHostStartup()
    {
        using var invalidFactory = _factory.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Passkey:MaxOutstandingCeremoniesPerApplication"] = "0"
                })));

        var exception = Assert.Throws<OptionsValidationException>(() => invalidFactory.CreateClient());

        Assert.Contains("bounded ceremony settings", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>Verifies application/caller mismatches fail before a ceremony is issued.</summary>
    [Theory]
    [InlineData("QuoteEngineBff", "web")]
    [InlineData("WebBff", "quote-engine")]
    public async Task BeginPasskeyAuthentication_UnboundServiceApplication_IsForbidden(
        string serviceName,
        string application)
    {
        using var client = CreateServiceClient(serviceName);

        using var response = await client.PostAsJsonAsync(BeginPath, new { application });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>Verifies anonymous callers cannot start a passkey ceremony.</summary>
    [Fact]
    public async Task BeginPasskeyAuthentication_AnonymousCaller_IsUnauthorized()
    {
        using var client = _factory.CreateClient();

        using var response = await client.PostAsJsonAsync(BeginPath, new { application = "web" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>Verifies service identity without the exchange permission cannot start a ceremony.</summary>
    [Fact]
    public async Task BeginPasskeyAuthentication_ServiceWithoutExchangePermission_IsForbidden()
    {
        using var client = CreateServiceClient("WebBff", includeExchangePermission: false);

        using var response = await client.PostAsJsonAsync(BeginPath, new { application = "web" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>Verifies v1 routes remain present but cannot execute the retired identity contract.</summary>
    [Theory]
    [InlineData(LegacyBeginPath)]
    [InlineData(LegacyCompletePath)]
    public async Task LegacyPasskeyAuthenticationRoute_IsContained(string path)
    {
        using var client = CreateServiceClient("WebBff");

        using var response = await client.PostAsJsonAsync(path, new
        {
            principal_id = Guid.NewGuid(),
            email = "forged@example.test"
        });

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var error = await response.Content.ReadFromJsonAsync<ErrorResponse>();
        Assert.Equal("passkey_authentication_unavailable", error?.Error);
    }

    /// <summary>Verifies caller-authored principal scoping is rejected.</summary>
    [Fact]
    public async Task BeginPasskeyAuthentication_PrincipalId_IsRejected()
    {
        using var client = CreateServiceClient("WebBff");

        using var response = await client.PostAsJsonAsync(BeginPath, new
        {
            application = "web",
            principal_id = Guid.NewGuid()
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var error = await response.Content.ReadFromJsonAsync<ErrorResponse>();
        Assert.Equal("passkey_flow_invalid", error?.Error);
    }

    /// <summary>Verifies a missing/replayed flow returns one generic error without identity data.</summary>
    [Fact]
    public async Task CompletePasskeyAuthentication_UnknownFlow_ReturnsGenericUnauthorized()
    {
        using var client = CreateServiceClient("WebBff");

        using var response = await client.PostAsJsonAsync(CompletePath, new
        {
            application = "web",
            flow_id = new string('A', 43),
            credential_id = "AQ",
            authenticator_data = new string('A', 50),
            client_data_json = "e30",
            signature = "AQ",
            user_handle = "AQ"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var payload = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("authentication_failed", payload.GetProperty("error").GetString());
        Assert.False(payload.TryGetProperty("principal_id", out _));
        Assert.False(payload.TryGetProperty("email", out _));
    }

    /// <summary>Verifies assertion fields are bounded before ceremony or credential processing.</summary>
    [Fact]
    public async Task CompletePasskeyAuthentication_OversizedClientData_IsRejectedByContract()
    {
        using var client = CreateServiceClient("WebBff");
        using var beginResponse = await client.PostAsJsonAsync(
            BeginPath,
            new { application = "web" });
        beginResponse.EnsureSuccessStatusCode();
        var begin = await beginResponse.Content.ReadFromJsonAsync<JsonElement>();
        var flowId = Assert.IsType<string>(begin.GetProperty("flow_id").GetString());

        using var response = await client.PostAsJsonAsync(CompletePath, new
        {
            application = "web",
            flow_id = flowId,
            credential_id = "AQ",
            authenticator_data = new string('A', 50),
            client_data_json = new string('A', 10_925),
            signature = "AQ",
            user_handle = "AQ"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var flowHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(flowId)));
        await using var scope = _factory.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        Assert.True(await dbContext.PasskeyAssertionCeremonies
            .AsNoTracking()
            .AnyAsync(candidate => candidate.FlowIdHash == flowHash));
    }

    private HttpClient CreateServiceClient(
        string serviceName,
        bool includeExchangePermission = true)
    {
        var claims = new Dictionary<string, string>
        {
            ["user_type"] = "service",
            ["service_name"] = serviceName
        };
        if (includeExchangePermission)
        {
            claims["permission"] = AuthPermissions.ExchangeIdentities;
        }

        var token = _rootFactory.CreateTestJwtToken(
            Guid.NewGuid().ToString(),
            ["service"],
            claims);
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        client.DefaultRequestHeaders.Add("X-Test-Client-IP", "127.0.0.1");
        return client;
    }
}
