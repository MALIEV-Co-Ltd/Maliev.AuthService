using Maliev.AuthService.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Infrastructure.Configurations;

/// <summary>
/// EF Core entity type configuration for <see cref="UserPrincipal"/>.
/// </summary>
public class UserPrincipalConfiguration : IEntityTypeConfiguration<UserPrincipal>
{
    /// <summary>Configures the <see cref="UserPrincipal"/> entity.</summary>
    /// <param name="builder">The entity type builder.</param>
    public void Configure(EntityTypeBuilder<UserPrincipal> builder)
    {
        builder.ToTable("user_principals");

        builder.HasKey(e => e.Id);
        builder.Property(e => e.Id).HasColumnName("id");

        builder.Property(e => e.Email).HasColumnName("email").HasMaxLength(255).IsRequired();
        builder.Property(e => e.FirstName).HasColumnName("first_name").HasMaxLength(100).IsRequired();
        builder.Property(e => e.LastName).HasColumnName("last_name").HasMaxLength(100).IsRequired();
        builder.Property(e => e.UserType).HasColumnName("user_type").IsRequired().HasConversion<string>();
        builder.Property(e => e.EmailVerifiedAtUtc).HasColumnName("email_verified_at_utc");
        builder.Property(e => e.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("NOW()");
        builder.Property(e => e.UpdatedAt).HasColumnName("updated_at").HasDefaultValueSql("NOW()");

        // Indexes
        builder.HasIndex(e => e.Email).IsUnique().HasDatabaseName("idx_user_principals_email");
        builder.HasIndex(e => e.UserType).HasDatabaseName("idx_user_principals_user_type");

        builder.Property<uint>("xmin")
            .HasColumnType("xid")
            .IsRowVersion();
    }
}
