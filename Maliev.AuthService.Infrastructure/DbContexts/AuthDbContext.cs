using Maliev.Aspire.ServiceDefaults.Database;
using Maliev.AuthService.Domain.Entities;
using MassTransit;
using Microsoft.EntityFrameworkCore;

namespace Maliev.AuthService.Infrastructure.DbContexts;

/// <summary>
/// EF Core database context for the Auth Service.
/// </summary>
public class AuthDbContext : DbContext
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuthDbContext"/> class.
    /// </summary>
    /// <param name="options">The DbContext options.</param>
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
    {
    }

    /// <summary>Gets or sets refresh tokens.</summary>
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    /// <summary>Gets or sets token families.</summary>
    public DbSet<TokenFamily> TokenFamilies => Set<TokenFamily>();

    /// <summary>Gets or sets revoked tokens.</summary>
    public DbSet<RevokedToken> RevokedTokens => Set<RevokedToken>();

    /// <summary>Gets or sets account lockouts.</summary>
    public DbSet<AccountLockout> AccountLockouts => Set<AccountLockout>();

    /// <summary>Gets or sets IP rate limits.</summary>
    public DbSet<IpRateLimit> IpRateLimits => Set<IpRateLimit>();

    /// <summary>Gets or sets auth audit logs.</summary>
    public DbSet<AuthAuditLog> AuthAuditLogs => Set<AuthAuditLog>();

    /// <summary>Gets or sets service credentials.</summary>
    public DbSet<ServiceCredential> ServiceCredentials => Set<ServiceCredential>();

    /// <summary>Gets or sets user principals.</summary>
    public DbSet<UserPrincipal> UserPrincipals => Set<UserPrincipal>();

    /// <summary>Gets or sets passkey credentials.</summary>
    public DbSet<PasskeyCredential> PasskeyCredentials => Set<PasskeyCredential>();

    /// <summary>Gets or sets short-lived passkey assertion ceremonies.</summary>
    public DbSet<PasskeyAssertionCeremony> PasskeyAssertionCeremonies => Set<PasskeyAssertionCeremony>();

    /// <summary>Gets or sets verification tokens.</summary>
    public DbSet<VerificationToken> VerificationTokens => Set<VerificationToken>();

    /// <summary>Gets or sets one-time Google identity exchange nonces.</summary>
    public DbSet<GoogleIdentityNonce> GoogleIdentityNonces => Set<GoogleIdentityNonce>();

    /// <inheritdoc/>
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.AddInboxStateEntity();
        modelBuilder.AddOutboxMessageEntity();
        modelBuilder.AddOutboxStateEntity();

        // Apply all configurations from the assembly
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(AuthDbContext).Assembly);

        // Apply PostgreSQL snake_case naming convention globally
        SnakeCaseNamingHelper.ApplySnakeCaseNaming(modelBuilder);
    }
}
