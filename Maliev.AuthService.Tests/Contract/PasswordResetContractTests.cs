using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Maliev.AuthService.Tests.Infrastructure;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

[Collection("AuthService Collection")]
public class PasswordResetContractTests : IntegrationTestBase
{
    public PasswordResetContractTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task POST_V1_Auth_PasswordResetRequest_DelegatesToCustomerService()
    {
        await CleanDatabaseAsync();
        var request = new
        {
            email = "customer@example.com"
        };

        var response = await Client.PostAsJsonAsync("/auth/v1/password-reset/request", request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);
        Assert.True(json.RootElement.GetProperty("accepted").GetBoolean());
    }

    [Fact]
    public async Task POST_V1_Auth_PasswordResetConfirm_DelegatesToCustomerService()
    {
        await CleanDatabaseAsync();
        var request = new
        {
            email = "customer@example.com",
            token = "reset-token",
            new_password = "NewPassword123456!"
        };

        var response = await Client.PostAsJsonAsync("/auth/v1/password-reset/confirm", request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);
        Assert.True(json.RootElement.GetProperty("reset").GetBoolean());
    }
}
