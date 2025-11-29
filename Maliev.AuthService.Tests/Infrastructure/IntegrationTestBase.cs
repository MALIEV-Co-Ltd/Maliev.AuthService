using Microsoft.VisualStudio.TestTools.UnitTesting;
using Maliev.AuthService.Tests.Contract;
using System.Net.Http;
using System.Threading.Tasks;

namespace Maliev.AuthService.Tests.Infrastructure;

/// <summary>
/// Base class for integration tests with proper disposal ordering
/// Factory is disposed BEFORE database cleanup to prevent race conditions
/// </summary>
public abstract class IntegrationTestBase
{
    protected HttpClient _client = null!;
    protected TestWebApplicationFactory _factory = null!;

    [TestInitialize]
    public void Setup()
    {
        // Synchronous setup to avoid MSTest async timing issues
        SetupAsync().GetAwaiter().GetResult();
    }

    private async Task SetupAsync()
    {
        // Clear connection pools FIRST to remove any ambient transaction contamination
        Npgsql.NpgsqlConnection.ClearAllPools();
        
        _factory = new TestWebApplicationFactory();
        await _factory.ResetDatabaseAsync();
        _client = _factory.CreateClient();
    }

    [TestCleanup]
    public void Cleanup()
    {
        // Synchronous cleanup to ensure proper ordering
        CleanupAsync().GetAwaiter().GetResult();
    }

    private async Task CleanupAsync()
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
