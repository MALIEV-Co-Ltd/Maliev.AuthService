using Maliev.AuthService.Tests.Contract;
using Xunit;

namespace Maliev.AuthService.Tests.Infrastructure;

/// <summary>
/// Base class for integration tests with proper disposal ordering using xUnit's IAsyncLifetime.
/// Factory is disposed BEFORE database cleanup to prevent race conditions.
/// </summary>
public abstract class IntegrationTestBase : IAsyncLifetime
{
    protected HttpClient _client = null!;
    protected TestWebApplicationFactory _factory = null!;

    public async Task InitializeAsync()
    {
        // Clear connection pools FIRST to remove any ambient transaction contamination
        Npgsql.NpgsqlConnection.ClearAllPools();
        
        _factory = new TestWebApplicationFactory();
        await _factory.ResetDatabaseAsync();
        _client = _factory.CreateClient();
    }

    public async Task DisposeAsync()
    {
        try
        {
            // Step 1: Dispose client first
            _client?.Dispose();
        }
        finally
        {
            try
            {
                // Step 2: Dispose factory BEFORE database cleanup
                // This ensures no pending async operations can write to DB during reset
                if (_factory != null)
                {
                    await _factory.DisposeAsync();
                }
            }
            finally
            {
                // Step 3: Clear connection pools to ensure clean state for next test
                Npgsql.NpgsqlConnection.ClearAllPools();
            }
        }
    }
}
