using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Data.Configurations;

/// <summary>
/// Entity Framework configuration for TokenFamily entity
/// </summary>
public class TokenFamilyConfiguration : IEntityTypeConfiguration<TokenFamily>
{
    public void Configure(EntityTypeBuilder<TokenFamily> builder)
    {
        builder.ToTable("token_families");

        builder.HasKey(tf => tf.FamilyId);

        builder.Property(tf => tf.FamilyId)
            .HasColumnName("family_id");

        builder.Property(tf => tf.UserId)
            .IsRequired()
            .HasMaxLength(255)
            .HasColumnName("user_id");

        builder.Property(tf => tf.UserType)
            .IsRequired()
            .HasConversion<string>()
            .HasColumnName("user_type");

        builder.Property(tf => tf.CreatedAt)
            .IsRequired()
            .HasColumnName("created_at");

        builder.Property(tf => tf.LastUsedAt)
            .IsRequired()
            .HasColumnName("last_used_at");

        // Indexes
        builder.HasIndex(tf => tf.UserId)
            .HasDatabaseName("ix_token_families_user_id");

        builder.HasIndex(tf => tf.LastUsedAt)
            .HasDatabaseName("ix_token_families_last_used_at");
    }
}
