using Maliev.AuthService.Data.Configurations;
using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace Maliev.AuthService.Data.DbContexts;

/// <summary>
/// Database context for the authentication service.
/// Manages refresh tokens, token families, and revoked access tokens.
/// </summary>
public class RefreshTokenDbContext : DbContext
{
    public RefreshTokenDbContext(DbContextOptions<RefreshTokenDbContext> options) : base(options)
    {
    }

    /// <summary>
    /// Refresh tokens stored in the database
    /// </summary>
    public DbSet<RefreshToken> RefreshTokens { get; set; } = null!;

    /// <summary>
    /// Token families for tracking token lineage
    /// </summary>
    public DbSet<TokenFamily> TokenFamilies { get; set; } = null!;

    /// <summary>
    /// Revoked access tokens
    /// </summary>
    public DbSet<RevokedAccessToken> RevokedAccessTokens { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Apply entity configurations
        modelBuilder.ApplyConfiguration(new RefreshTokenConfiguration());
        modelBuilder.ApplyConfiguration(new TokenFamilyConfiguration());
        modelBuilder.ApplyConfiguration(new RevokedAccessTokenConfiguration());
    }
}
