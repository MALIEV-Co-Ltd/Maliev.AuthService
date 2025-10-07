using Maliev.AuthService.Data.DbContexts;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Maliev.AuthService.Data;

/// <summary>
/// Design-time factory for EF Core migrations.
/// Uses environment variable AuthDbContext for connection string.
/// </summary>
public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<AuthDbContext>
{
    public AuthDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("AuthDbContext")
            ?? throw new InvalidOperationException(
                "AuthDbContext environment variable not set. " +
                "Set it before running migrations: " +
                "export AuthDbContext=\"Server=localhost;Port=5432;Database=auth_app_db;User Id=postgres;Password=yourpassword;\"");

        var optionsBuilder = new DbContextOptionsBuilder<AuthDbContext>();
        optionsBuilder.UseNpgsql(connectionString);

        return new AuthDbContext(optionsBuilder.Options);
    }
}
