using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;

using Maliev.AuthService.Tests.Infrastructure;

namespace Maliev.AuthService.Tests.Contract;

[TestClass]
public class HealthCheckContractTests : IntegrationTestBase
{

    [TestMethod]
    public async Task GET_Liveness_Returns200()
    {
        // Act
        var response = await _client.GetAsync("/auth/liveness");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadAsStringAsync();
        content.Should().NotBeNullOrEmpty();
    }

    [TestMethod]
    public async Task GET_Readiness_DatabaseHealthy_Returns200()
    {
        // Act
        var response = await _client.GetAsync("/auth/readiness");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadAsStringAsync();
        content.Should().Contain("Healthy");
    }
}
