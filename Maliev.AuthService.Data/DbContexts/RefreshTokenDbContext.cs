using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;

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

        public async Task CleanExpiredAndRevokedTokensAsync()
        {
#if DEBUG
            var tokensToClean = await RefreshTokens
                .Where(rt => rt.Expires < DateTime.UtcNow && rt.Revoked != null)
                .ToListAsync();

            if (tokensToClean.Any())
            {
                RefreshTokens.RemoveRange(tokensToClean);
                await SaveChangesAsync();
            }
#else
            await RefreshTokens
                .Where(rt => rt.Expires < DateTime.UtcNow && rt.Revoked != null)
                .ExecuteDeleteAsync();
#endif
        }
    }
}