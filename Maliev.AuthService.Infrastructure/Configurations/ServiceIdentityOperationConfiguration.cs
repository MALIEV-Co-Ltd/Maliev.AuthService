using Maliev.AuthService.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Infrastructure.Configurations;

/// <summary>Configures durable service identity lifecycle operations.</summary>
public sealed class ServiceIdentityOperationConfiguration : IEntityTypeConfiguration<ServiceIdentityOperation>
{
    /// <inheritdoc/>
    public void Configure(EntityTypeBuilder<ServiceIdentityOperation> builder)
    {
        builder.ToTable("service_identity_operations");
        builder.HasKey(entity => entity.Id);
        builder.Property(entity => entity.Id).HasColumnName("id");
        builder.Property(entity => entity.WorkloadId).HasColumnName("workload_id").HasMaxLength(100).IsRequired();
        builder.Property(entity => entity.Kind).HasColumnName("kind").HasConversion<string>().HasMaxLength(16);
        builder.Property(entity => entity.RequestHash).HasColumnName("request_hash").HasMaxLength(64).IsRequired();
        builder.Property(entity => entity.ActorId).HasColumnName("actor_id");
        builder.Property(entity => entity.State).HasColumnName("state").HasConversion<string>().HasMaxLength(32);
        builder.Property(entity => entity.IamPrincipalId).HasColumnName("iam_principal_id");
        builder.Property(entity => entity.IamProfileVersion).HasColumnName("iam_profile_version");
        builder.Property(entity => entity.IamRoleId).HasColumnName("iam_role_id").HasMaxLength(160);
        builder.Property(entity => entity.CredentialVersionId).HasColumnName("credential_version_id");
        builder.Property(entity => entity.CreatedAt).HasColumnName("created_at");
        builder.Property(entity => entity.UpdatedAt).HasColumnName("updated_at");
        builder.HasIndex(entity => new { entity.WorkloadId, entity.Kind })
            .HasDatabaseName("idx_service_identity_operations_workload_kind");
        builder.Property<uint>("xmin").HasColumnType("xid").IsRowVersion();
    }
}
