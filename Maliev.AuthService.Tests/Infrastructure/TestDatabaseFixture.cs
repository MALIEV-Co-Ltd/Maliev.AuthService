using Maliev.AuthService.Data.DbContexts;
using Microsoft.EntityFrameworkCore;
using Testcontainers.PostgreSql;

namespace Maliev.AuthService.Tests.Infrastructure;

/// <summary>
/// Manages PostgreSQL test database lifecycle using Testcontainers
/// Provides clean database for each test class
/// </summary>
public class TestDatabaseFixture : IDisposable
{
    private PostgreSqlContainer? _postgresContainer;
    public string ConnectionString { get; private set; } = string.Empty;
    private bool _initialized = false;

    public async Task InitializeAsync()
    {
        if (_initialized) return;

        _postgresContainer = new PostgreSqlBuilder()
            .WithImage("postgres:18")
            .WithDatabase("auth_test_db")
            .WithUsername("postgres")
            .WithPassword("test_password")
            .Build();

        await _postgresContainer.StartAsync();
        ConnectionString = _postgresContainer.GetConnectionString();

        await using var context = CreateDbContext();
        await context.Database.MigrateAsync();
        await SeedTestServiceCredentialAsync(context);

        _initialized = true;
    }

    private static async Task SeedTestServiceCredentialAsync(AuthDbContext context)
    {
        var testServiceCredential = new Maliev.AuthService.Data.Entities.ServiceCredential
        {
            Id = Guid.NewGuid(),
            ClientId = "service-dev-customer-api",
            ClientSecretHash = "536cd80fe9c61705de47dacb3fc7c4d3c4c331841afe942a9966abc5e4ad70ef",
            ServiceName = "Customer API",
            IsActive = true,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        var existingCredential = await context.ServiceCredentials
            .FirstOrDefaultAsync(sc => sc.ClientId == testServiceCredential.ClientId);

        if (existingCredential == null)
        {
            context.ServiceCredentials.Add(testServiceCredential);
            await context.SaveChangesAsync();
        }
    }

    public void Dispose()
    {
        if (_postgresContainer != null)
        {
            _postgresContainer.DisposeAsync().AsTask().Wait();
        }
    }

    public AuthDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseNpgsql(ConnectionString)
            .Options;

        return new AuthDbContext(options);
    }

    public async Task ClearDatabaseAsync()
    {
        await using (var context = CreateDbContext())
        {
            // Delete in order of dependency (child first, then parent)
            await context.Database.ExecuteSqlRawAsync("DELETE FROM revoked_tokens");
            await context.Database.ExecuteSqlRawAsync("DELETE FROM refresh_tokens");
            await context.Database.ExecuteSqlRawAsync("DELETE FROM token_families");
            await context.Database.ExecuteSqlRawAsync("DELETE FROM account_lockouts");
            await context.Database.ExecuteSqlRawAsync("DELETE FROM ip_rate_limits");
            await context.Database.ExecuteSqlRawAsync("DELETE FROM auth_audit_logs");
            
            // Do NOT delete service_credentials as they are static test data
            
            await context.SaveChangesAsync();
            context.ChangeTracker.Clear(); // Ensure no entities are tracked
        }
        
        // Clear all connection pools to ensure clean state for next test
        // This prevents connection leakage and ensures full isolation
        await Task.Delay(100); // Small delay to ensure context is fully disposed
        Npgsql.NpgsqlConnection.ClearAllPools();
        await Task.Delay(100); // Small delay after clearing pools
    }

    public async Task SeedTestDataAsync(Action<AuthDbContext> seedAction)
    {
        await using var context = CreateDbContext();
        seedAction(context);
        await context.SaveChangesAsync();
    }
}
