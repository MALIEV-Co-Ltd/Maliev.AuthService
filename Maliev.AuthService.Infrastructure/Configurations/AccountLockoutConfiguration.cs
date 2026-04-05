using Maliev.AuthService.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Infrastructure.Configurations;

/// <summary>
/// EF Core entity type configuration for <see cref="AccountLockout"/>.
/// </summary>
public class AccountLockoutConfiguration : IEntityTypeConfiguration<AccountLockout>
{
    /// <summary>Configures the <see cref="AccountLockout"/> entity.</summary>
    /// <param name="builder">The entity type builder.</param>
    public void Configure(EntityTypeBuilder<AccountLockout> builder)
    {
        builder.ToTable("account_lockouts");

        builder.HasKey(e => e.Id);
        builder.Property(e => e.Id).HasColumnName("id");

        builder.Property(e => e.UserId).HasColumnName("user_id").IsRequired();
        builder.Property(e => e.UserType).HasColumnName("user_type").IsRequired().HasConversion<string>();
        builder.Property(e => e.FailedAttempts).HasColumnName("failed_attempts").HasDefaultValue(0);
        builder.Property(e => e.LockedUntil).HasColumnName("locked_until");
        builder.Property(e => e.LastAttemptAt).HasColumnName("last_attempt_at").HasDefaultValueSql("NOW()");
        builder.Property(e => e.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("NOW()");
        builder.Property(e => e.UpdatedAt).HasColumnName("updated_at").HasDefaultValueSql("NOW()");

        // Indexes
        builder.Property<uint>("xmin")
            .HasColumnType("xid")
            .IsRowVersion();

        builder.HasIndex(e => new { e.UserId, e.UserType }).IsUnique().HasDatabaseName("idx_account_lockouts_user_id_user_type");
        builder.HasIndex(e => e.LockedUntil).HasDatabaseName("idx_account_lockouts_locked_until");
    }
}
