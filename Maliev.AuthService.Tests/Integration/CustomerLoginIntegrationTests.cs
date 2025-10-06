using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Maliev.AuthService.Tests.Contract;
using Xunit;

namespace Maliev.AuthService.Tests.Integration;

/// <summary>
/// Integration tests for customer login flow with real database.
/// Tests full authentication lifecycle for customer users.
/// </summary>
[Trait("Category", "Integration")]
public class CustomerLoginIntegrationTests : IntegrationTestBase
{
    [Fact]
    public async Task CustomerLogin_WithValidCredentials_ReturnsTokensAndStoresRefreshToken()
    {
        // Arrange
        var request = new
        {
            username = "customer@example.com",
            password = "SecurePassword123!",
            user_type = "customer"
        };

        // Act
        var response = await Client!.PostAsJsonAsync("/auth/login", request);

        // Assert - This will FAIL until implementation
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadFromJsonAsync<LoginResponse>();
        content.Should().NotBeNull();
        content!.AccessToken.Should().NotBeNullOrEmpty();
        content.RefreshToken.Should().NotBeNullOrEmpty();
        content.TokenType.Should().Be("Bearer");
        content.ExpiresIn.Should().BeGreaterThan(0);

        // TODO: Verify refresh token is stored in database
        // TODO: Verify token family is created
    }

    [Fact]
    public async Task CustomerLogin_WithInvalidPassword_Returns401()
    {
        // Arrange
        var request = new
        {
            username = "customer@example.com",
            password = "WrongPassword",
            user_type = "customer"
        };

        // Act
        var response = await Client!.PostAsJsonAsync("/auth/login", request);

        // Assert - This will FAIL until implementation
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task CustomerLogin_WithNonexistentUser_Returns401()
    {
        // Arrange
        var request = new
        {
            username = "nonexistent@example.com",
            password = "AnyPassword123!",
            user_type = "customer"
        };

        // Act
        var response = await Client!.PostAsJsonAsync("/auth/login", request);

        // Assert - This will FAIL until implementation
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}
