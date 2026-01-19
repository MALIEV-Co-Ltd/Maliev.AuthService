using System.Text.Json;
using Maliev.AuthService.Tests.Contract;
using Xunit;

namespace Maliev.AuthService.Tests.Infrastructure;

/// <summary>
/// Base class for integration tests using shared factory via IClassFixture.
/// Factory is shared across all tests in a class to avoid Docker container exhaustion.
/// </summary>
public abstract class IntegrationTestBase : IClassFixture<TestWebApplicationFactory>, IAsyncLifetime
{
    protected readonly TestWebApplicationFactory Factory;
    protected readonly HttpClient Client;

    protected static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        PropertyNameCaseInsensitive = true
    };


    protected static readonly string[] AdminRoles = { "admin" };

    protected IntegrationTestBase(TestWebApplicationFactory factory)
    {
        Factory = factory;
        Client = Factory.CreateAuthenticatedClient("test-admin", AdminRoles);
        // Set a consistent IP address for rate limiting tests
        Client.DefaultRequestHeaders.Add("X-Test-Client-IP", "127.0.0.1");
    }

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        // Clean database after all tests in this class complete
        await Factory.CleanDatabaseAsync();
    }

    /// <summary>
    /// Cleans the database to ensure test isolation.
    /// Call this at the start of each test method to ensure a clean state.
    /// </summary>
    protected async Task CleanDatabaseAsync()
    {
        await Factory.CleanDatabaseAsync();
    }
}
