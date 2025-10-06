using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

[Trait("Category", "Contract")]
public class RefreshContractTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public RefreshContractTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Refresh_WithValidToken_ReturnsNewTokens()
    {
        // Arrange
        var request = new { refresh_token = "valid_refresh_token_here" };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/refresh", request);

        // Assert - This should FAIL until endpoint is implemented
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadFromJsonAsync<LoginResponse>();
        content.Should().NotBeNull();
        content!.AccessToken.Should().NotBeNullOrEmpty();
        content.RefreshToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Refresh_WithReusedToken_Returns401AndInvalidatesFamily()
    {
        // Arrange
        var request = new { refresh_token = "previously_used_token" };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/refresh", request);

        // Assert - This should FAIL until token reuse detection is implemented
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        var content = await response.Content.ReadFromJsonAsync<ErrorResponse>();
        content!.Error.Should().Contain("token_family_invalidated");
    }
}
