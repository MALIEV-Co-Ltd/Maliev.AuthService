using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Data.Configurations;

public class TokenFamilyConfiguration : IEntityTypeConfiguration<TokenFamily>
{
    public void Configure(EntityTypeBuilder<TokenFamily> builder)
    {
        builder.ToTable("token_families");

        builder.HasKey(e => e.FamilyId);
        builder.Property(e => e.FamilyId).HasColumnName("family_id");

        builder.Property(e => e.UserId).HasColumnName("user_id").IsRequired();
        builder.Property(e => e.UserType).HasColumnName("user_type").IsRequired().HasConversion<string>();
        builder.Property(e => e.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("NOW()");
        builder.Property(e => e.LastRefreshAt).HasColumnName("last_refresh_at").HasDefaultValueSql("NOW()");

        // Indexes
        builder.HasIndex(e => e.UserId).HasDatabaseName("idx_token_families_user_id");
    }
}
