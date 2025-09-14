using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Maliev.AuthService.Data.DbContexts
{
    public class RefreshTokenDbContext : DbContext
    {
        public RefreshTokenDbContext(DbContextOptions<RefreshTokenDbContext> options) : base(options)
        {
        }

        public DbSet<RefreshToken> RefreshTokens { get; set; } = null!;

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
        }

        public async Task CleanExpiredAndRevokedTokensAsync(ILogger<RefreshTokenDbContext>? logger = null)
        {
            try
            {
                // Try to use ExecuteDeleteAsync for better performance (PostgreSQL, SQL Server, etc.)
                var deletedCount = await RefreshTokens
                    .Where(rt => rt.Expires < DateTime.UtcNow && rt.Revoked != null)
                    .ExecuteDeleteAsync();
                
                logger?.LogInformation("Cleaned up {DeletedCount} expired and revoked refresh tokens using ExecuteDeleteAsync", deletedCount);
            }
            catch (InvalidOperationException)
            {
                // Fall back to traditional approach for providers that don't support ExecuteDeleteAsync (like InMemory)
                var tokensToClean = await RefreshTokens
                    .Where(rt => rt.Expires < DateTime.UtcNow && rt.Revoked != null)
                    .ToListAsync();

                if (tokensToClean.Any())
                {
                    RefreshTokens.RemoveRange(tokensToClean);
                    await SaveChangesAsync();
                    logger?.LogInformation("Cleaned up {DeletedCount} expired and revoked refresh tokens using traditional approach", tokensToClean.Count);
                }
                else
                {
                    logger?.LogInformation("No expired and revoked refresh tokens to clean up");
                }
            }
        }
    }
}