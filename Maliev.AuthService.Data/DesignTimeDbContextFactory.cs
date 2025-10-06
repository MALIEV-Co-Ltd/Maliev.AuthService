using Maliev.AuthService.Data.DbContexts;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Maliev.AuthService.Data;

/// <summary>
/// Factory for creating RefreshTokenDbContext at design time (for EF Core migrations).
/// This allows migrations to be created without running the full application.
/// </summary>
public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<RefreshTokenDbContext>
{
    public RefreshTokenDbContext CreateDbContext(string[] args)
    {
        // Use a temporary connection string for migrations
        // The actual connection string will be provided at runtime via configuration
        var connectionString = Environment.GetEnvironmentVariable("RefreshTokenDbContext")
            ?? "Server=localhost;Port=5432;Database=auth_db_design;User Id=postgres;Password=postgres;";

        var optionsBuilder = new DbContextOptionsBuilder<RefreshTokenDbContext>()
            .UseNpgsql(connectionString);

        return new RefreshTokenDbContext(optionsBuilder.Options);
    }
}
