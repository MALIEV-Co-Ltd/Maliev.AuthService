using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Maliev.AuthService.Tests.Infrastructure;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

[Collection("AuthService Collection")]
public class AuthenticationAdditionalContractTests : IntegrationTestBase
{
    public AuthenticationAdditionalContractTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task POST_V1_Auth_Login_EmptyUserType_Returns400()
    {
        await CleanDatabaseAsync();
        var request = new
        {
            username = "user@example.com",
            password = TestConstants.DummyPassword,
            user_type = ""
        };

        var response = await Client.PostAsJsonAsync("/auth/v1/login", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task POST_V1_Auth_Login_InvalidUserType_Returns400()
    {
        await CleanDatabaseAsync();
        var request = new
        {
            username = "user@example.com",
            password = TestConstants.DummyPassword,
            user_type = "admin"
        };

        var response = await Client.PostAsJsonAsync("/auth/v1/login", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task POST_V1_Auth_Login_EmployeeCredentials_ReturnsEmployeeUserType()
    {
        await CleanDatabaseAsync();
        var request = new
        {
            username = "employee@maliev.com",
            password = TestConstants.DummyPassword,
            user_type = "employee"
        };

        var response = await Client.PostAsJsonAsync("/auth/v1/login", request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        var user = json.RootElement.GetProperty("user");
        Assert.Equal("employee", user.GetProperty("user_type").GetString());
    }

    [Fact]
    public async Task POST_V1_Auth_Login_SuccessfulLogin_ContainsExpectedClaims()
    {
        await CleanDatabaseAsync();
        var request = new
        {
            username = "customer@example.com",
            password = TestConstants.DummyPassword,
            user_type = "customer"
        };

        var response = await Client.PostAsJsonAsync("/auth/v1/login", request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        var accessToken = json.RootElement.GetProperty("access_token").GetString();
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(accessToken);

        Assert.NotNull(token.Subject);
        Assert.NotNull(token.Id);

        var userTypeClaim = token.Claims.FirstOrDefault(c => c.Type == "user_type");
        Assert.NotNull(userTypeClaim);
        Assert.Equal("customer", userTypeClaim.Value);
    }

    [Fact]
    public async Task POST_V1_Auth_Login_MissingBody_Returns400()
    {
        await CleanDatabaseAsync();

        var response = await Client.PostAsJsonAsync("/auth/v1/login", new object());

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task POST_V1_Auth_Login_AfterSuccessfulLogin_SecondLoginWithSameUser_ReturnsNewTokens()
    {
        await CleanDatabaseAsync();
        var request = new
        {
            username = "customer@example.com",
            password = TestConstants.DummyPassword,
            user_type = "customer"
        };

        var firstResponse = await Client.PostAsJsonAsync("/auth/v1/login", request);
        var firstContent = await firstResponse.Content.ReadAsStringAsync();
        var firstJson = JsonDocument.Parse(firstContent);
        var firstToken = firstJson.RootElement.GetProperty("access_token").GetString();

        await Task.Delay(100); // Small delay to ensure different timestamps

        var secondResponse = await Client.PostAsJsonAsync("/auth/v1/login", request);
        var secondContent = await secondResponse.Content.ReadAsStringAsync();
        var secondJson = JsonDocument.Parse(secondContent);
        var secondToken = secondJson.RootElement.GetProperty("access_token").GetString();

        Assert.NotEqual(firstToken, secondToken);
    }
}
