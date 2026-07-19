using Maliev.AuthService.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Infrastructure.Configurations;

/// <summary>
/// EF Core entity type configuration for <see cref="ServiceCredential"/>.
/// </summary>
public class ServiceCredentialConfiguration : IEntityTypeConfiguration<ServiceCredential>
{
    /// <summary>Configures the <see cref="ServiceCredential"/> entity.</summary>
    /// <param name="builder">The entity type builder.</param>
    public void Configure(EntityTypeBuilder<ServiceCredential> builder)
    {
        builder.ToTable("service_credentials", table =>
        {
            table.HasCheckConstraint(
                "ck_service_credentials_managed_binding",
                "workload_id IS NULL OR (principal_id IS NOT NULL AND profile_version IS NOT NULL AND profile_version > 0 AND role_id IS NOT NULL)");
        });

        builder.HasKey(e => e.Id);
        builder.Property(e => e.Id).HasColumnName("id");

        builder.Property(e => e.ClientId).HasColumnName("client_id").HasMaxLength(100).IsRequired();
        builder.Property(e => e.PrincipalId).HasColumnName("principal_id");
        builder.Property(e => e.ClientSecretHash).HasColumnName("client_secret_hash").HasMaxLength(64).IsRequired();
        builder.Property(e => e.ServiceName).HasColumnName("service_name").HasMaxLength(100).IsRequired();
        builder.Property(e => e.WorkloadId).HasColumnName("workload_id").HasMaxLength(100);
        builder.Property(e => e.ProfileVersion).HasColumnName("profile_version");
        builder.Property(e => e.RoleId).HasColumnName("role_id").HasMaxLength(160);
        builder.Property(e => e.IsActive).HasColumnName("is_active").HasDefaultValue(true);
        builder.Property(e => e.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("NOW()");
        builder.Property(e => e.UpdatedAt).HasColumnName("updated_at").HasDefaultValueSql("NOW()");
        builder.Property(e => e.RevokedAt).HasColumnName("revoked_at");

        // Indexes
        builder.HasIndex(e => e.ClientId).IsUnique().HasDatabaseName("idx_service_credentials_client_id");
        builder.HasIndex(e => e.WorkloadId).IsUnique().HasFilter("workload_id IS NOT NULL")
            .HasDatabaseName("idx_service_credentials_workload_id");
        builder.HasIndex(e => e.IsActive).HasDatabaseName("idx_service_credentials_is_active");

        builder.Property<uint>("xmin")
            .HasColumnType("xid")
            .IsRowVersion();
    }
}
