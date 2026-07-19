using Maliev.AuthService.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Infrastructure.Configurations;

/// <summary>Configures hashed service credential versions.</summary>
public sealed class ServiceCredentialVersionConfiguration : IEntityTypeConfiguration<ServiceCredentialVersion>
{
    /// <inheritdoc/>
    public void Configure(EntityTypeBuilder<ServiceCredentialVersion> builder)
    {
        builder.ToTable("service_credential_versions", table =>
        {
            table.HasCheckConstraint("ck_service_credential_versions_version", "version > 0");
            table.HasCheckConstraint(
                "ck_service_credential_versions_hash",
                "length(secret_hash) = 64 AND secret_hash ~ '^[0-9A-F]{64}$'");
            table.HasCheckConstraint(
                "ck_service_credential_versions_status",
                "status IN ('Pending', 'Active', 'Grace', 'Revoked')");
            table.HasCheckConstraint(
                "ck_service_credential_versions_expiry",
                "hard_expires_at > created_at");
        });

        builder.HasKey(entity => entity.Id);
        builder.Property(entity => entity.Id).HasColumnName("id");
        builder.Property(entity => entity.ServiceCredentialId).HasColumnName("service_credential_id");
        builder.Property(entity => entity.Version).HasColumnName("version");
        builder.Property(entity => entity.SecretHash).HasColumnName("secret_hash").HasMaxLength(64).IsRequired();
        builder.Property(entity => entity.Status).HasColumnName("status").HasConversion<string>().HasMaxLength(16);
        builder.Property(entity => entity.CreatedAt).HasColumnName("created_at");
        builder.Property(entity => entity.ActivatedAt).HasColumnName("activated_at");
        builder.Property(entity => entity.GraceExpiresAt).HasColumnName("grace_expires_at");
        builder.Property(entity => entity.HardExpiresAt).HasColumnName("hard_expires_at");
        builder.Property(entity => entity.RevokedAt).HasColumnName("revoked_at");

        builder.HasOne(entity => entity.ServiceCredential)
            .WithMany(entity => entity.Versions)
            .HasForeignKey(entity => entity.ServiceCredentialId)
            .OnDelete(DeleteBehavior.Restrict);
        builder.HasIndex(entity => new { entity.ServiceCredentialId, entity.Version })
            .IsUnique()
            .HasDatabaseName("idx_service_credential_versions_credential_version");
        builder.HasIndex(entity => new { entity.ServiceCredentialId, entity.Status })
            .HasDatabaseName("idx_service_credential_versions_credential_status");
        builder.HasIndex(entity => entity.ServiceCredentialId)
            .IsUnique()
            .HasFilter("status = 'Active'")
            .HasDatabaseName("idx_service_credential_versions_one_active");
        builder.Property<uint>("xmin").HasColumnType("xid").IsRowVersion();
    }
}
