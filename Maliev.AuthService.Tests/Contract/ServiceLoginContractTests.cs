using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

using Maliev.AuthService.Tests.Infrastructure;

namespace Maliev.AuthService.Tests.Contract;

[TestClass]
public class ServiceLoginContractTests : IntegrationTestBase
{

    [TestMethod]
    public async Task POST_V1_Auth_Service_Login_ValidCredentials_Returns200WithServiceToken()
    {
        // Arrange
        var request = new
        {
            client_id = "service-dev-customer-api",
            client_secret = "valid_service_secret"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/v1/service/login", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        json.RootElement.GetProperty("access_token").GetString().Should().NotBeNullOrEmpty();
        json.RootElement.GetProperty("token_type").GetString().Should().Be("Bearer");
        json.RootElement.GetProperty("expires_in").GetInt32().Should().BeGreaterThan(0);

        // Service tokens should not have refresh tokens
        json.RootElement.TryGetProperty("refresh_token", out _).Should().BeFalse();
    }

    [TestMethod]
    public async Task POST_V1_Auth_Service_Login_InvalidClientId_Returns401()
    {
        // Arrange - Use properly formatted but non-existent client ID
        var request = new
        {
            client_id = "service-dev-nonexistent",
            client_secret = "some_secret"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/v1/service/login", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        json.RootElement.GetProperty("error").GetString().Should().NotBeNullOrEmpty();
    }

    [TestMethod]
    public async Task POST_V1_Auth_Service_Login_InvalidClientSecret_Returns401()
    {
        // Arrange
        var request = new
        {
            client_id = "service-dev-customer-api",
            client_secret = "wrong_secret"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/auth/v1/service/login", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}
