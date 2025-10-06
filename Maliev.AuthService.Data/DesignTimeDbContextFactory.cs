using Maliev.AuthService.Data.DbContexts;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Maliev.AuthService.Data;

/// <summary>
/// Factory for creating AuthDbContext at design time (for EF Core migrations).
/// This allows migrations to be created without running the full application.
/// </summary>
public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<AuthDbContext>
{
    public AuthDbContext CreateDbContext(string[] args)
    {
        // Use a temporary connection string for migrations
        // The actual connection string will be provided at runtime via configuration
        var connectionString = Environment.GetEnvironmentVariable("AuthDbContext")
            ?? "Server=localhost;Port=5432;Database=auth_db_design;User Id=postgres;Password=postgres;";

        var optionsBuilder = new DbContextOptionsBuilder<AuthDbContext>()
            .UseNpgsql(connectionString);

        return new AuthDbContext(optionsBuilder.Options);
    }
}
