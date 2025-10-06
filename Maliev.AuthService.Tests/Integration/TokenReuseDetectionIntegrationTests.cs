using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Maliev.AuthService.Tests.Contract;
using Xunit;

namespace Maliev.AuthService.Tests.Integration;

/// <summary>
/// Integration tests for token reuse detection (RFC 9700 security requirement).
/// Verifies that reusing a refresh token invalidates the entire token family.
/// </summary>
[Trait("Category", "Integration")]
public class TokenReuseDetectionIntegrationTests : IntegrationTestBase
{
    [Fact]
    public async Task RefreshToken_ReuseDetected_InvalidatesEntireTokenFamily()
    {
        // Arrange
        var loginRequest = new { username = "customer@example.com", password = "Password123!", user_type = "customer" };
        var loginResponse = await Client!.PostAsJsonAsync("/auth/login", loginRequest);
        var loginContent = await loginResponse.Content.ReadFromJsonAsync<LoginResponse>();

        var refreshRequest1 = new { refresh_token = loginContent!.RefreshToken };

        // Act 1: Use refresh token first time (valid)
        var refreshResponse1 = await Client!.PostAsJsonAsync("/auth/refresh", refreshRequest1);
        refreshResponse1.StatusCode.Should().Be(HttpStatusCode.OK);

        // Act 2: Attempt to reuse the SAME refresh token (security violation)
        var refreshResponse2 = await Client!.PostAsJsonAsync("/auth/refresh", refreshRequest1);

        // Assert - This will FAIL until implementation
        refreshResponse2.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        var errorContent = await refreshResponse2.Content.ReadFromJsonAsync<ErrorResponse>();
        errorContent.Should().NotBeNull();
        errorContent!.Error.Should().Contain("token_family_invalidated");

        // TODO: Verify entire token family is revoked in database
        // TODO: Verify all tokens in family are marked as revoked
    }

    [Fact]
    public async Task RefreshToken_AfterFamilyInvalidation_AllTokensInFamilyAreRejected()
    {
        await Task.CompletedTask;
        // Test that after reuse detection, ALL tokens in the family are rejected
        // This will FAIL until implementation

        // TODO: Login -> Refresh 1 -> Refresh 2 -> Attempt to reuse token from Refresh 1
        // TODO: Verify reuse detection triggers family invalidation
        // TODO: Attempt to use token from Refresh 2 -> Should also be rejected
    }
}
