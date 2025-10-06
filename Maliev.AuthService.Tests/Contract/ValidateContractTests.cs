using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

[Trait("Category", "Contract")]
public class ValidateContractTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public ValidateContractTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Validate_WithValidToken_ReturnsUserIdentity()
    {
        // Arrange
        var request = new { access_token = "valid_jwt_token" };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/validate", request);

        // Assert - This should FAIL until endpoint is implemented
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadFromJsonAsync<ValidateResponse>();
        content.Should().NotBeNull();
        content!.UserId.Should().NotBeNullOrEmpty();
        content.UserType.Should().BeOneOf("customer", "employee");
        content.Roles.Should().NotBeNull();
        content.Permissions.Should().NotBeNull();
    }

    [Fact]
    public async Task Validate_WithRevokedToken_Returns401()
    {
        // Arrange
        var request = new { access_token = "revoked_jwt_token" };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/validate", request);

        // Assert - This should FAIL until revocation checking is implemented
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        var content = await response.Content.ReadFromJsonAsync<ErrorResponse>();
        content!.Error.Should().Contain("token_revoked");
    }
}
