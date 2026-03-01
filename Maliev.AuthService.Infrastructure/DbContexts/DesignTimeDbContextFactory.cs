using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Maliev.AuthService.Infrastructure.DbContexts;

/// <summary>
/// Design-time factory for EF Core migrations.
/// Uses environment variable AuthDbContext for connection string.
/// </summary>
public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<AuthDbContext>
{
    /// <inheritdoc/>
    public AuthDbContext CreateDbContext(string[] args)
    {
        // Prefer environment variable for connection string, fallback to design-time default if not set
        var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__AuthDbContext")
            ?? "Host=localhost;Database=auth_design;Username=postgres;Password=postgres";

        var optionsBuilder = new DbContextOptionsBuilder<AuthDbContext>();
        optionsBuilder.UseNpgsql(connectionString);

        return new AuthDbContext(optionsBuilder.Options);
    }
}
