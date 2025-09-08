using Maliev.AuthService.Data.DbContexts;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Maliev.AuthService.Data
{
    public class RefreshTokenDbContextFactory : IDesignTimeDbContextFactory<RefreshTokenDbContext>
    {
        public RefreshTokenDbContext CreateDbContext(string[] args)
        {
            var optionsBuilder = new DbContextOptionsBuilder<RefreshTokenDbContext>();

            // Use generic environment variable for connection string during design time
            var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__Default");

            if (string.IsNullOrEmpty(connectionString))
            {
                // Fallback connection string for design time - AuthService uses auth_app_db
                connectionString = "Host=localhost;Port=5433;Database=auth_app_db;Username=postgres;Password=temp;SslMode=Disable";
            }

            optionsBuilder.UseNpgsql(connectionString);

            return new RefreshTokenDbContext(optionsBuilder.Options);
        }
    }
}