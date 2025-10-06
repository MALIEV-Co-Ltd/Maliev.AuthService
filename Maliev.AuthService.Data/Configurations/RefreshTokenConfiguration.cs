using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Data.Configurations;

/// <summary>
/// Entity Framework configuration for RefreshToken entity
/// </summary>
public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("refresh_tokens");

        builder.HasKey(rt => rt.Id);

        builder.Property(rt => rt.TokenHash)
            .IsRequired()
            .HasMaxLength(64) // SHA-256 produces 64 hex characters
            .HasColumnName("token_hash");

        builder.Property(rt => rt.UserId)
            .IsRequired()
            .HasMaxLength(255)
            .HasColumnName("user_id");

        builder.Property(rt => rt.UserType)
            .IsRequired()
            .HasConversion<string>()
            .HasColumnName("user_type");

        builder.Property(rt => rt.FamilyId)
            .IsRequired()
            .HasColumnName("family_id");

        builder.Property(rt => rt.CreatedAt)
            .IsRequired()
            .HasColumnName("created_at");

        builder.Property(rt => rt.ExpiresAt)
            .IsRequired()
            .HasColumnName("expires_at");

        builder.Property(rt => rt.IsRevoked)
            .IsRequired()
            .HasDefaultValue(false)
            .HasColumnName("is_revoked");

        builder.Property(rt => rt.IsUsed)
            .IsRequired()
            .HasDefaultValue(false)
            .HasColumnName("is_used");

        builder.Property(rt => rt.RevokedAt)
            .HasColumnName("revoked_at");

        builder.Property(rt => rt.Version)
            .IsRowVersion()
            .HasColumnName("version");

        // Indexes for performance
        builder.HasIndex(rt => rt.TokenHash)
            .IsUnique()
            .HasDatabaseName("ix_refresh_tokens_token_hash");

        builder.HasIndex(rt => rt.FamilyId)
            .HasDatabaseName("ix_refresh_tokens_family_id");

        builder.HasIndex(rt => rt.UserId)
            .HasDatabaseName("ix_refresh_tokens_user_id");

        builder.HasIndex(rt => rt.ExpiresAt)
            .HasDatabaseName("ix_refresh_tokens_expires_at");

        // Foreign key to token family
        builder.HasOne(rt => rt.TokenFamily)
            .WithMany(tf => tf.RefreshTokens)
            .HasForeignKey(rt => rt.FamilyId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
