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

            var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__RefreshTokenDbContext");

            optionsBuilder.UseNpgsql(connectionString);

            return new RefreshTokenDbContext(optionsBuilder.Options);
        }
    }
}