using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Net.Http.Json;

using Maliev.AuthService.Tests.Infrastructure;

namespace Maliev.AuthService.Tests.Contract;

[TestClass]
public class DebugTest : IntegrationTestBase
{

    [TestMethod]
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
        true.Should().BeTrue();
    }
}
