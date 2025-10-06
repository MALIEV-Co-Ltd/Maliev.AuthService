using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Maliev.AuthService.Tests.Contract;
using Xunit;

namespace Maliev.AuthService.Tests.Integration;

/// <summary>
/// Integration tests for employee login flow with real database.
/// Tests full authentication lifecycle for employee users.
/// </summary>
[Trait("Category", "Integration")]
public class EmployeeLoginIntegrationTests : IntegrationTestBase
{
    [Fact]
    public async Task EmployeeLogin_WithValidCredentials_ReturnsTokensAndStoresRefreshToken()
    {
        // Arrange
        var request = new
        {
            username = "employee@maliev.com",
            password = "EmployeePass123!",
            user_type = "employee"
        };

        // Act
        var response = await Client!.PostAsJsonAsync("/auth/login", request);

        // Assert - This will FAIL until implementation
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadFromJsonAsync<LoginResponse>();
        content.Should().NotBeNull();
        content!.AccessToken.Should().NotBeNullOrEmpty();
        content!.RefreshToken.Should().NotBeNullOrEmpty();
        content!.TokenType.Should().Be("Bearer");
    }

    [Fact]
    public async Task EmployeeLogin_WithCustomerCredentials_Returns401()
    {
        // Arrange - Try to login as employee with customer account
        var request = new
        {
            username = "customer@example.com",
            password = "CustomerPass123!",
            user_type = "employee"
        };

        // Act
        var response = await Client!.PostAsJsonAsync("/auth/login", request);

        // Assert - This will FAIL until implementation
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}
