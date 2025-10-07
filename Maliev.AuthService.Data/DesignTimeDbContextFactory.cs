using Maliev.AuthService.Data.DbContexts;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Maliev.AuthService.Data;

/// <summary>
/// Design-time factory for EF Core migrations.
/// Uses environment variable RefreshTokenDbContext for connection string.
/// </summary>
public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<AuthDbContext>
{
    public AuthDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("RefreshTokenDbContext")
            ?? throw new InvalidOperationException(
                "RefreshTokenDbContext environment variable not set. " +
                "Set it before running migrations: " +
                "export RefreshTokenDbContext=\"Server=localhost;Port=5432;Database=auth_app_db;User Id=postgres;Password=yourpassword;\"");

        var optionsBuilder = new DbContextOptionsBuilder<AuthDbContext>();
        optionsBuilder.UseNpgsql(connectionString);

        return new AuthDbContext(optionsBuilder.Options);
    }
}
