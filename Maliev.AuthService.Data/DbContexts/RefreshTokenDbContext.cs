using Maliev.AuthService.Common.Exceptions;
using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Threading;

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

        public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                return await base.SaveChangesAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                throw new DatabaseOperationException("Failed to save changes to database", ex);
            }
        }

        public async Task CleanExpiredAndRevokedTokensAsync(ILogger<RefreshTokenDbContext>? logger = null, CancellationToken cancellationToken = default)
        {
            try
            {
                // Try to use ExecuteDeleteAsync for better performance (PostgreSQL, SQL Server, etc.)
                var deletedCount = await RefreshTokens
                    .Where(rt => rt.Expires < DateTime.UtcNow && rt.Revoked != null)
                    .ExecuteDeleteAsync(cancellationToken);
                
                logger?.LogInformation("Cleaned up {DeletedCount} expired and revoked refresh tokens using ExecuteDeleteAsync", deletedCount);
            }
            catch (InvalidOperationException)
            {
                try
                {
                    // Fall back to traditional approach for providers that don't support ExecuteDeleteAsync (like InMemory)
                    var tokensToClean = await RefreshTokens
                        .Where(rt => rt.Expires < DateTime.UtcNow && rt.Revoked != null)
                        .ToListAsync(cancellationToken);

                    if (tokensToClean.Any())
                    {
                        RefreshTokens.RemoveRange(tokensToClean);
                        await SaveChangesAsync(cancellationToken);
                        logger?.LogInformation("Cleaned up {DeletedCount} expired and revoked refresh tokens using traditional approach", tokensToClean.Count);
                    }
                    else
                    {
                        logger?.LogInformation("No expired and revoked refresh tokens to clean up");
                    }
                }
                catch (Exception ex)
                {
                    logger?.LogError(ex, "Failed to clean expired and revoked tokens using traditional approach");
                    throw new DatabaseOperationException("Failed to clean expired and revoked tokens using traditional approach", ex);
                }
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Failed to clean expired and revoked tokens using ExecuteDeleteAsync");
                throw new DatabaseOperationException("Failed to clean expired and revoked tokens using ExecuteDeleteAsync", ex);
            }
        }
    }
}