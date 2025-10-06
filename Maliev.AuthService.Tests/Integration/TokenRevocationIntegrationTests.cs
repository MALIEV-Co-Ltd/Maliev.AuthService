using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Maliev.AuthService.Tests.Contract;
using Xunit;

namespace Maliev.AuthService.Tests.Integration;

/// <summary>
/// Integration tests for token revocation functionality.
/// Tests access token revocation and validation against revoked tokens.
/// </summary>
[Trait("Category", "Integration")]
public class TokenRevocationIntegrationTests : IntegrationTestBase
{
    [Fact]
    public async Task RevokeAccessToken_ValidToken_StoresRevocationInDatabase()
    {
        // Arrange
        var loginRequest = new { username = "customer@example.com", password = "Password123!", user_type = "customer" };
        var loginResponse = await Client!.PostAsJsonAsync("/auth/login", loginRequest);
        var loginContent = await loginResponse.Content.ReadFromJsonAsync<LoginResponse>();

        var revokeRequest = new { access_token = loginContent!.AccessToken, reason = "user_logout" };

        // Act
        var revokeResponse = await Client!.PostAsJsonAsync("/auth/revoke", revokeRequest);

        // Assert - This will FAIL until implementation
        revokeResponse.StatusCode.Should().Be(HttpStatusCode.NoContent);

        // TODO: Verify revocation is stored in database
        // TODO: Verify JTI is in RevokedAccessTokens table
    }

    [Fact]
    public async Task ValidateToken_RevokedToken_Returns401()
    {
        // Arrange - Login, then revoke
        var loginRequest = new { username = "customer@example.com", password = "Password123!", user_type = "customer" };
        var loginResponse = await Client!.PostAsJsonAsync("/auth/login", loginRequest);
        var loginContent = await loginResponse.Content.ReadFromJsonAsync<LoginResponse>();

        var revokeRequest = new { access_token = loginContent!.AccessToken, reason = "user_logout" };
        await Client!.PostAsJsonAsync("/auth/revoke", revokeRequest);

        // Act - Try to validate revoked token
        var validateRequest = new { access_token = loginContent.AccessToken };
        var validateResponse = await Client!.PostAsJsonAsync("/auth/validate", validateRequest);

        // Assert - This will FAIL until implementation
        validateResponse.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        var errorContent = await validateResponse.Content.ReadFromJsonAsync<ErrorResponse>();
        errorContent!.Error.Should().Contain("token_revoked");
    }
}
