using Maliev.AuthService.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Infrastructure.Configurations;

/// <summary>
/// EF Core entity type configuration for <see cref="IpRateLimit"/>.
/// </summary>
public class IpRateLimitConfiguration : IEntityTypeConfiguration<IpRateLimit>
{
    /// <summary>Configures the <see cref="IpRateLimit"/> entity.</summary>
    /// <param name="builder">The entity type builder.</param>
    public void Configure(EntityTypeBuilder<IpRateLimit> builder)
    {
        builder.ToTable("ip_rate_limits");

        builder.HasKey(e => e.Id);
        builder.Property(e => e.Id).HasColumnName("id");

        builder.Property(e => e.IpAddress).HasColumnName("ip_address").HasMaxLength(45).IsRequired();
        builder.Property(e => e.FailedAttempts).HasColumnName("failed_attempts").HasDefaultValue(0);
        builder.Property(e => e.BlockedUntil).HasColumnName("blocked_until");
        builder.Property(e => e.WindowStart).HasColumnName("window_start").HasDefaultValueSql("NOW()");
        builder.Property(e => e.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("NOW()");
        builder.Property(e => e.UpdatedAt).HasColumnName("updated_at").HasDefaultValueSql("NOW()");
        builder.Property(e => e.Version)
            .HasColumnName("version")
            .IsRowVersion()
            .HasDefaultValueSql("'\\x0000000000000000'::bytea")
            .ValueGeneratedOnAddOrUpdate()
            .IsRequired();

        // Indexes
        builder.HasIndex(e => e.IpAddress).IsUnique().HasDatabaseName("idx_ip_rate_limits_ip_address");
        builder.HasIndex(e => e.BlockedUntil).HasDatabaseName("idx_ip_rate_limits_blocked_until");
    }
}
