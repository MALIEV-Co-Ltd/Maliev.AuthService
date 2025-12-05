using System.Net;
using System.Net.Http.Json;
using Maliev.AuthService.Tests.Infrastructure;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

public class DebugTest : IntegrationTestBase
{

    [Fact]
    public async Task Debug_Login_ShowActualResponse()
    {
        var request = new
        {
            username = "customer@example.com",
            password = "ValidPassword123!",
            user_type = "customer"
        };

        var response = await _client.PostAsJsonAsync("/auth/v1/login", request);

        var body = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"Status: {response.StatusCode}");
        Console.WriteLine($"Body: {body}");

        // Just output, don't fail
        Assert.True(true);
    }
}
