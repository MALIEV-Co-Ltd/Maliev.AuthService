using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

[Trait("Category", "Contract")]
public class RevokeContractTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public RevokeContractTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Revoke_WithValidToken_Returns204()
    {
        // Arrange
        var request = new { access_token = "valid_jwt_token", reason = "user_logout" };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/revoke", request);

        // Assert - This should FAIL until endpoint is implemented
        response.StatusCode.Should().Be(HttpStatusCode.NoContent);
    }

    [Fact]
    public async Task Revoke_WithInvalidToken_Returns401()
    {
        // Arrange
        var request = new { access_token = "invalid_token", reason = "user_logout" };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/revoke", request);

        // Assert - This should FAIL until endpoint is implemented
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}
