using Maliev.AuthService.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Infrastructure.Configurations;

/// <summary>
/// EF Core entity type configuration for <see cref="RefreshToken"/>.
/// </summary>
public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    /// <summary>Configures the <see cref="RefreshToken"/> entity.</summary>
    /// <param name="builder">The entity type builder.</param>
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("refresh_tokens");

        builder.HasKey(e => e.Id);
        builder.Property(e => e.Id).HasColumnName("id");

        builder.Property(e => e.FamilyId).HasColumnName("family_id").IsRequired();
        builder.Property(e => e.UserId).HasColumnName("user_id").IsRequired();
        builder.Property(e => e.UserType).HasColumnName("user_type").IsRequired().HasConversion<string>();
        builder.Property(e => e.TokenHash).HasColumnName("token_hash").HasMaxLength(64).IsRequired();
        builder.Property(e => e.Email).HasColumnName("email").HasMaxLength(255);
        builder.Property(e => e.Name).HasColumnName("name").HasMaxLength(255);
        builder.Property(e => e.IsUsed).HasColumnName("is_used").HasDefaultValue(false);
        builder.Property(e => e.UsedAt).HasColumnName("used_at");
        builder.Property(e => e.ExpiresAt).HasColumnName("expires_at").IsRequired();
        builder.Property(e => e.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("NOW()");
        builder.Property(e => e.IpAddress).HasColumnName("ip_address").HasMaxLength(45);
        builder.Property<uint>("xmin")
            .HasColumnType("xid")
            .IsRowVersion();

        // Indexes
        builder.HasIndex(e => e.TokenHash).IsUnique().HasDatabaseName("idx_refresh_tokens_token_hash");
        builder.HasIndex(e => e.FamilyId).HasDatabaseName("idx_refresh_tokens_family_id");
        builder.HasIndex(e => e.UserId).HasDatabaseName("idx_refresh_tokens_user_id");
        builder.HasIndex(e => e.ExpiresAt).HasDatabaseName("idx_refresh_tokens_expires_at");

        // Foreign key
        builder.HasOne(e => e.Family)
            .WithMany(f => f.RefreshTokens)
            .HasForeignKey(e => e.FamilyId)
            .HasConstraintName("fk_refresh_tokens_token_families")
            .OnDelete(DeleteBehavior.Cascade);
    }
}
