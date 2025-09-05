using Maliev.AuthService.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace Maliev.AuthService.Api.Data
{
    public class RefreshTokenDbContext : DbContext
    {
        public RefreshTokenDbContext(DbContextOptions<RefreshTokenDbContext> options) : base(options)
        {
        }

        public DbSet<RefreshToken> RefreshTokens { get; set; } = null!;

        public async Task CleanExpiredAndRevokedTokensAsync()
        {
            var tokensToClean = await RefreshTokens
                .Where(rt => rt.Expires < DateTime.UtcNow && rt.Revoked != null)
                .ToListAsync();

            RefreshTokens.RemoveRange(tokensToClean);
            await SaveChangesAsync();
        }
    }
}