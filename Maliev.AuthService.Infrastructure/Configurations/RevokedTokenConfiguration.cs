using Maliev.AuthService.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Infrastructure.Configurations;

/// <summary>
/// EF Core entity type configuration for <see cref="RevokedToken"/>.
/// </summary>
public class RevokedTokenConfiguration : IEntityTypeConfiguration<RevokedToken>
{
    /// <summary>Configures the <see cref="RevokedToken"/> entity.</summary>
    /// <param name="builder">The entity type builder.</param>
    public void Configure(EntityTypeBuilder<RevokedToken> builder)
    {
        builder.ToTable("revoked_tokens");

        builder.HasKey(e => e.Id);
        builder.Property(e => e.Id).HasColumnName("id");

        builder.Property(e => e.Jti).HasColumnName("jti").HasMaxLength(100).IsRequired();
        builder.Property(e => e.UserId).HasColumnName("user_id").IsRequired();
        builder.Property(e => e.UserType).HasColumnName("user_type").IsRequired().HasConversion<string>();
        builder.Property(e => e.RevokedAt).HasColumnName("revoked_at").HasDefaultValueSql("NOW()");
        builder.Property(e => e.ExpiresAt).HasColumnName("expires_at").IsRequired();
        builder.Property(e => e.Reason).HasColumnName("reason").HasMaxLength(100).IsRequired();

        // Indexes
        builder.HasIndex(e => e.Jti).IsUnique().HasDatabaseName("idx_revoked_tokens_jti");
        builder.HasIndex(e => e.ExpiresAt).HasDatabaseName("idx_revoked_tokens_expires_at");
        builder.HasIndex(e => e.UserId).HasDatabaseName("idx_revoked_tokens_user_id");
    }
}
