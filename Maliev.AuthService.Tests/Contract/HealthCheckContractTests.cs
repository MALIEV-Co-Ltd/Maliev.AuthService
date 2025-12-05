using System.Net;
using Maliev.AuthService.Tests.Infrastructure;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

public class HealthCheckContractTests : IntegrationTestBase
{

    [Fact]
    public async Task GET_Liveness_Returns200()
    {
        // Act
        var response = await _client.GetAsync("/auth/liveness");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        Assert.NotNull(content);
        Assert.NotEmpty(content);
    }

    [Fact]
    public async Task GET_Readiness_DatabaseHealthy_Returns200()
    {
        // Act
        var response = await _client.GetAsync("/auth/readiness");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("Healthy", content);
    }
}
