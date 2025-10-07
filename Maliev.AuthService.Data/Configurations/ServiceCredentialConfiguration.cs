using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Data.Configurations;

public class ServiceCredentialConfiguration : IEntityTypeConfiguration<ServiceCredential>
{
    public void Configure(EntityTypeBuilder<ServiceCredential> builder)
    {
        builder.ToTable("service_credentials");

        builder.HasKey(e => e.Id);
        builder.Property(e => e.Id).HasColumnName("id");

        builder.Property(e => e.ClientId).HasColumnName("client_id").HasMaxLength(100).IsRequired();
        builder.Property(e => e.ClientSecretHash).HasColumnName("client_secret_hash").HasMaxLength(64).IsRequired();
        builder.Property(e => e.ServiceName).HasColumnName("service_name").HasMaxLength(100).IsRequired();
        builder.Property(e => e.IsActive).HasColumnName("is_active").HasDefaultValue(true);
        builder.Property(e => e.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("NOW()");
        builder.Property(e => e.UpdatedAt).HasColumnName("updated_at").HasDefaultValueSql("NOW()");

        // Indexes
        builder.HasIndex(e => e.ClientId).IsUnique().HasDatabaseName("idx_service_credentials_client_id");
        builder.HasIndex(e => e.IsActive).HasDatabaseName("idx_service_credentials_is_active");
    }
}
