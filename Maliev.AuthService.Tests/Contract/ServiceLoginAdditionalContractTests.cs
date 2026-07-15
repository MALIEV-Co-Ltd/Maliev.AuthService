using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Maliev.AuthService.Tests.Infrastructure;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

[Collection("AuthService Collection")]
public class ServiceLoginAdditionalContractTests : IntegrationTestBase
{
    public ServiceLoginAdditionalContractTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_ValidCredentials_ContainsServiceType()
    {
        await CleanDatabaseAsync();
        var request = new
        {
            client_id = "service-dev-customer-api",
            client_secret = TestConstants.DummyValidServiceSecret
        };

        var response = await Client.PostAsJsonAsync("/auth/v1/service/login", request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        var user = json.RootElement.GetProperty("user");
        Assert.Equal("service", user.GetProperty("user_type").GetString());
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_MissingClientId_Returns400()
    {
        await CleanDatabaseAsync();

        var response = await Client.PostAsJsonAsync("/auth/v1/service/login", new object());

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_MissingClientSecret_Returns400()
    {
        await CleanDatabaseAsync();
        var request = new { client_id = "test" };

        var response = await Client.PostAsJsonAsync("/auth/v1/service/login", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_InactiveClient_Returns401()
    {
        await CleanDatabaseAsync();

        using var context = Factory.CreateDbContext();
        var credential = context.ServiceCredentials.FirstOrDefault();
        if (credential != null)
        {
            credential.IsActive = false;
            await context.SaveChangesAsync();
        }

        var request = new
        {
            client_id = "service-dev-customer-api",
            client_secret = TestConstants.DummyValidServiceSecret
        };

        var response = await Client.PostAsJsonAsync("/auth/v1/service/login", request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_ValidCredentials_ReturnsConfiguredServiceExpiry()
    {
        await CleanDatabaseAsync();
        var request = new
        {
            client_id = "service-dev-customer-api",
            client_secret = TestConstants.DummyValidServiceSecret
        };

        var response = await Client.PostAsJsonAsync("/auth/v1/service/login", request);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.Equal(900, json.RootElement.GetProperty("expires_in").GetInt32());
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_ValidCredentials_ContainsServiceName()
    {
        await CleanDatabaseAsync();
        var request = new
        {
            client_id = "service-dev-customer-api",
            client_secret = TestConstants.DummyValidServiceSecret
        };

        var response = await Client.PostAsJsonAsync("/auth/v1/service/login", request);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        var user = json.RootElement.GetProperty("user");
        Assert.NotNull(user.GetProperty("name").GetString());
    }
}
