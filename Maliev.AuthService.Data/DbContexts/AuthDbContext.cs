using Maliev.Aspire.ServiceDefaults.Database;
using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace Maliev.AuthService.Data.DbContexts;

public class AuthDbContext : DbContext
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
    {
    }

    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<TokenFamily> TokenFamilies => Set<TokenFamily>();
    public DbSet<RevokedToken> RevokedTokens => Set<RevokedToken>();
    public DbSet<AccountLockout> AccountLockouts => Set<AccountLockout>();
    public DbSet<IpRateLimit> IpRateLimits => Set<IpRateLimit>();
    public DbSet<AuthAuditLog> AuthAuditLogs => Set<AuthAuditLog>();
    public DbSet<ServiceCredential> ServiceCredentials => Set<ServiceCredential>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Apply all configurations from the assembly
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(AuthDbContext).Assembly);

        // Apply PostgreSQL snake_case naming convention globally
        SnakeCaseNamingHelper.ApplySnakeCaseNaming(modelBuilder);
    }
}
