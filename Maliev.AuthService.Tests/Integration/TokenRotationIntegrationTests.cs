using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Maliev.AuthService.Tests.Contract;
using Xunit;

namespace Maliev.AuthService.Tests.Integration;

/// <summary>
/// Integration tests for token rotation (RFC 9700 compliance).
/// Verifies that refresh tokens are rotated on each use.
/// </summary>
[Trait("Category", "Integration")]
public class TokenRotationIntegrationTests : IntegrationTestBase
{
    [Fact]
    public async Task RefreshToken_ValidToken_RotatesAndReturnsNewTokens()
    {
        // Arrange
        var loginRequest = new
        {
            username = "customer@example.com",
            password = "Password123!",
            user_type = "customer"
        };

        // Act 1: Login to get initial tokens
        var loginResponse = await Client!.PostAsJsonAsync("/auth/login", loginRequest);
        var loginContent = await loginResponse.Content.ReadFromJsonAsync<LoginResponse>();

        // Act 2: Use refresh token
        var refreshRequest = new { refresh_token = loginContent!.RefreshToken };
        var refreshResponse = await Client!.PostAsJsonAsync("/auth/refresh", refreshRequest);

        // Assert - This will FAIL until implementation
        refreshResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var refreshContent = await refreshResponse.Content.ReadFromJsonAsync<LoginResponse>();
        refreshContent.Should().NotBeNull();
        refreshContent!.AccessToken.Should().NotBeNullOrEmpty();
        refreshContent.RefreshToken.Should().NotBeNullOrEmpty();

        // New refresh token should be different from old one
        refreshContent.RefreshToken.Should().NotBe(loginContent.RefreshToken);

        // TODO: Verify old refresh token is marked as used in database
        // TODO: Verify new refresh token belongs to same family
    }

    [Fact]
    public async Task RefreshToken_MultipleRotations_MaintainsFamilyLineage()
    {
        await Task.CompletedTask;
        // Test that multiple rotations maintain the same family ID
        // This will FAIL until implementation

        // TODO: Login -> Refresh 1 -> Refresh 2 -> Refresh 3
        // TODO: Verify all tokens belong to same family
        // TODO: Verify each token is marked as used after rotation
    }
}
