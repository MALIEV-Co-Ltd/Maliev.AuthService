using Maliev.AuthService.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Infrastructure.Configurations;

/// <summary>
/// EF Core entity type configuration for <see cref="VerificationToken"/>.
/// </summary>
public class VerificationTokenConfiguration : IEntityTypeConfiguration<VerificationToken>
{
    /// <summary>Configures the <see cref="VerificationToken"/> entity.</summary>
    /// <param name="builder">The entity type builder.</param>
    public void Configure(EntityTypeBuilder<VerificationToken> builder)
    {
        builder.ToTable("verification_tokens");

        builder.HasKey(e => e.Id);
        builder.Property(e => e.Id).HasColumnName("id");

        builder.Property(e => e.PrincipalId).HasColumnName("principal_id").IsRequired();
        builder.Property(e => e.TokenHash).HasColumnName("token_hash").HasMaxLength(64).IsRequired();
        builder.Property(e => e.Email).HasColumnName("email").HasMaxLength(255).IsRequired();
        builder.Property(e => e.ExpiresAt).HasColumnName("expires_at").IsRequired();
        builder.Property(e => e.IsUsed).HasColumnName("is_used").HasDefaultValue(false);
        builder.Property(e => e.UsedAt).HasColumnName("used_at");
        builder.Property(e => e.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("NOW()");

        // Indexes
        builder.HasIndex(e => e.TokenHash).IsUnique().HasDatabaseName("idx_verification_tokens_token_hash");
        builder.HasIndex(e => e.PrincipalId).HasDatabaseName("idx_verification_tokens_principal_id");
        builder.HasIndex(e => e.ExpiresAt).HasDatabaseName("idx_verification_tokens_expires_at");

        builder.Property<uint>("xmin")
            .HasColumnType("xid")
            .IsRowVersion();
    }
}
