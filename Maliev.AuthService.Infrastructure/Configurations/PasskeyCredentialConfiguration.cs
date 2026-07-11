using Maliev.AuthService.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Infrastructure.Configurations;

/// <summary>
/// EF Core entity type configuration for <see cref="PasskeyCredential"/>.
/// </summary>
public class PasskeyCredentialConfiguration : IEntityTypeConfiguration<PasskeyCredential>
{
    /// <summary>Configures the <see cref="PasskeyCredential"/> entity.</summary>
    /// <param name="builder">The entity type builder.</param>
    public void Configure(EntityTypeBuilder<PasskeyCredential> builder)
    {
        builder.ToTable("passkey_credentials");

        builder.HasKey(e => e.Id);
        builder.Property(e => e.Id).HasColumnName("id");

        builder.Property(e => e.PrincipalId).HasColumnName("principal_id").IsRequired();
        builder.Property(e => e.CredentialId).HasColumnName("credential_id").HasMaxLength(1024).IsRequired();
        builder.Property(e => e.PublicKey).HasColumnName("public_key").IsRequired();
        builder.Property(e => e.PublicKeyCose).HasColumnName("public_key_cose");
        builder.Property(e => e.UserHandle).HasColumnName("user_handle").HasMaxLength(64);
        builder.Property(e => e.RegistrationVerificationVersion)
            .HasColumnName("registration_verification_version")
            .HasDefaultValue(0)
            .IsRequired();
        builder.Property(e => e.DeviceName).HasColumnName("device_name").HasMaxLength(256).IsRequired();
        builder.Property(e => e.Aaguid).HasColumnName("aaguid").HasMaxLength(64);
        builder.Property(e => e.SignCount).HasColumnName("sign_count").IsRequired();
        builder.Property(e => e.VerifiedSignCount).HasColumnName("verified_sign_count");
        builder.Property(e => e.IsBackupEligible).HasColumnName("is_backup_eligible");
        builder.Property(e => e.IsBackedUp).HasColumnName("is_backed_up");
        builder.Property(e => e.CreatedAtUtc).HasColumnName("created_at_utc").HasDefaultValueSql("NOW()");
        builder.Property(e => e.LastUsedAtUtc).HasColumnName("last_used_at_utc");

        // Indexes
        builder.HasIndex(e => e.PrincipalId).HasDatabaseName("idx_passkey_credentials_principal_id");
        builder.HasIndex(e => e.CredentialId).IsUnique().HasDatabaseName("idx_passkey_credentials_credential_id");

        builder.ToTable(table =>
        {
            table.HasCheckConstraint(
                "ck_passkey_credentials_registration_verification_version",
                "registration_verification_version >= 0");
            table.HasCheckConstraint(
                "ck_passkey_credentials_verified_sign_count",
                "verified_sign_count IS NULL OR (verified_sign_count >= 0 AND verified_sign_count <= 4294967295)");
        });

        builder.Property<uint>("xmin")
            .HasColumnType("xid")
            .IsRowVersion();
    }
}
