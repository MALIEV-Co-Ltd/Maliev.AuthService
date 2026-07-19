using System.Net;
using Maliev.AuthService.Tests.Infrastructure;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

[Collection("AuthService Collection")]
public class HealthCheckContractTests : IntegrationTestBase
{
    public HealthCheckContractTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task GET_Liveness_Returns200()
    {
        await CleanDatabaseAsync();
        // Act
        var response = await Client.GetAsync("/auth/liveness");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        Assert.NotNull(content);
        Assert.NotEmpty(content);
    }

    [Fact]
    public async Task GET_Readiness_DatabaseHealthy_Returns200()
    {
        await CleanDatabaseAsync();
        // Act
        var response = await Client.GetAsync("/auth/readiness");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("Healthy", content);
    }
}
