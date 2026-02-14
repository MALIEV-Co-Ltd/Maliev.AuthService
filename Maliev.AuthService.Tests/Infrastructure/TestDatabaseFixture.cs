using Maliev.AuthService.Data.DbContexts;
using Microsoft.EntityFrameworkCore;
using Testcontainers.PostgreSql;
using Testcontainers.Redis;
using Testcontainers.RabbitMq;

namespace Maliev.AuthService.Tests.Infrastructure;

/// <summary>
/// Manages PostgreSQL, Redis, and RabbitMQ test containers using Testcontainers
/// Provides clean infrastructure for each test class
/// </summary>
public class TestDatabaseFixture : IDisposable
{
    private PostgreSqlContainer? _postgresContainer;
    private RedisContainer? _redisContainer;
    private RabbitMqContainer? _rabbitmqContainer;
    public string ConnectionString { get; private set; } = string.Empty;
    public string RedisConnectionString { get; private set; } = string.Empty;
    public string RabbitMqConnectionString { get; private set; } = string.Empty;
    private bool _initialized = false;

    public async Task InitializeAsync()
    {
        if (_initialized) return;

        _postgresContainer = new PostgreSqlBuilder().WithName("postgres:18-alpine")
            .WithDatabase("auth_test_db")
            .WithUsername("postgres")
            .WithPassword("test_password")
            .Build();

        _redisContainer = new RedisBuilder().WithName("redis:8.4-alpine")
            .Build();

        _rabbitmqContainer = new RabbitMqBuilder().WithName("rabbitmq:4.2-alpine")
            .Build();

        // Start all containers in parallel
        await Task.WhenAll(
            _postgresContainer.StartAsync(),
            _redisContainer.StartAsync(),
            _rabbitmqContainer.StartAsync()
        );

        ConnectionString = _postgresContainer.GetConnectionString();
        RedisConnectionString = _redisContainer.GetConnectionString();
        RabbitMqConnectionString = _rabbitmqContainer.GetConnectionString();

        // Wait for Redis to be ready
        using (var connection = await StackExchange.Redis.ConnectionMultiplexer.ConnectAsync(RedisConnectionString))
        {
            await connection.GetDatabase().PingAsync();
        }

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
            PrincipalId = Guid.Parse("11111111-1111-1111-1111-111111111111"), // Test principal ID for IAM integration
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
        if (_redisContainer != null)
        {
            _redisContainer.DisposeAsync().AsTask().Wait();
        }
        if (_rabbitmqContainer != null)
        {
            _rabbitmqContainer.DisposeAsync().AsTask().Wait();
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
