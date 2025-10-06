using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Data.Configurations;

/// <summary>
/// Entity Framework configuration for RevokedAccessToken entity
/// </summary>
public class RevokedAccessTokenConfiguration : IEntityTypeConfiguration<RevokedAccessToken>
{
    public void Configure(EntityTypeBuilder<RevokedAccessToken> builder)
    {
        builder.ToTable("revoked_access_tokens");

        builder.HasKey(rat => rat.Jti);

        builder.Property(rat => rat.Jti)
            .IsRequired()
            .HasMaxLength(255)
            .HasColumnName("jti");

        builder.Property(rat => rat.RevokedAt)
            .IsRequired()
            .HasColumnName("revoked_at");

        builder.Property(rat => rat.ExpiresAt)
            .IsRequired()
            .HasColumnName("expires_at");

        builder.Property(rat => rat.Reason)
            .HasMaxLength(500)
            .HasColumnName("reason");

        // Index for cleanup queries
        builder.HasIndex(rat => rat.ExpiresAt)
            .HasDatabaseName("ix_revoked_access_tokens_expires_at");

        // Index for lookup by JTI
        builder.HasIndex(rat => rat.Jti)
            .IsUnique()
            .HasDatabaseName("ix_revoked_access_tokens_jti");
    }
}
