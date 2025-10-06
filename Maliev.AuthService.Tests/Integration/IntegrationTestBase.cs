using DotNet.Testcontainers.Builders;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Testcontainers.PostgreSql;
using Xunit;

namespace Maliev.AuthService.Tests.Integration;

/// <summary>
/// Base class for integration tests with PostgreSQL Testcontainer.
/// Provides a real database instance for testing.
/// </summary>
public class IntegrationTestBase : IAsyncLifetime
{
    protected PostgreSqlContainer? PostgresContainer { get; private set; }
    protected WebApplicationFactory<Program>? Factory { get; private set; }
    protected HttpClient? Client { get; private set; }
    protected string? ConnectionString { get; private set; }

    public async Task InitializeAsync()
    {
        // Create and start PostgreSQL container
        PostgresContainer = new PostgreSqlBuilder()
            .WithImage("postgres:17")
            .WithDatabase("auth_test_db")
            .WithUsername("test_user")
            .WithPassword("test_password")
            .WithWaitStrategy(Wait.ForUnixContainer().UntilPortIsAvailable(5432))
            .Build();

        await PostgresContainer.StartAsync();
        ConnectionString = PostgresContainer.GetConnectionString();

        // Create WebApplicationFactory with test database
        Factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureTestServices(services =>
                {
                    // Remove existing DbContext configuration
                    services.RemoveAll(typeof(DbContextOptions<Data.DbContexts.RefreshTokenDbContext>));

                    // Add test database configuration
                    services.AddDbContext<Data.DbContexts.RefreshTokenDbContext>(options =>
                    {
                        options.UseNpgsql(ConnectionString);
                    });

                    // Build service provider and ensure database is created
                    var serviceProvider = services.BuildServiceProvider();
                    using var scope = serviceProvider.CreateScope();
                    var dbContext = scope.ServiceProvider.GetRequiredService<Data.DbContexts.RefreshTokenDbContext>();
                    dbContext.Database.EnsureCreated();
                });

                builder.UseEnvironment("Testing");
            });

        Client = Factory.CreateClient();
    }

    public async Task DisposeAsync()
    {
        Client?.Dispose();
        Factory?.Dispose();

        if (PostgresContainer != null)
        {
            await PostgresContainer.DisposeAsync();
        }
    }

    /// <summary>
    /// Clears all data from the database between tests.
    /// </summary>
    protected async Task ClearDatabaseAsync()
    {
        if (Factory == null) return;

        using var scope = Factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<Data.DbContexts.RefreshTokenDbContext>();

        dbContext.RefreshTokens.RemoveRange(dbContext.RefreshTokens);
        dbContext.TokenFamilies.RemoveRange(dbContext.TokenFamilies);
        dbContext.RevokedAccessTokens.RemoveRange(dbContext.RevokedAccessTokens);

        await dbContext.SaveChangesAsync();
    }
}
