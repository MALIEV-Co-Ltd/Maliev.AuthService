using Maliev.AuthService.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Infrastructure.Configurations;

/// <summary>
/// EF Core entity type configuration for <see cref="AuthAuditLog"/>.
/// </summary>
public class AuthAuditLogConfiguration : IEntityTypeConfiguration<AuthAuditLog>
{
    /// <summary>Configures the <see cref="AuthAuditLog"/> entity.</summary>
    /// <param name="builder">The entity type builder.</param>
    public void Configure(EntityTypeBuilder<AuthAuditLog> builder)
    {
        builder.ToTable("auth_audit_logs");

        builder.HasKey(e => e.Id);
        builder.Property(e => e.Id).HasColumnName("id");

        builder.Property(e => e.UserId).HasColumnName("user_id");
        builder.Property(e => e.UserType).HasColumnName("user_type").HasConversion<string>();
        builder.Property(e => e.Action).HasColumnName("action").HasMaxLength(50).IsRequired();
        builder.Property(e => e.IpAddress).HasColumnName("ip_address").HasMaxLength(45).IsRequired();
        builder.Property(e => e.UserAgent).HasColumnName("user_agent");
        builder.Property(e => e.Success).HasColumnName("success").IsRequired();
        builder.Property(e => e.FailureReason).HasColumnName("failure_reason").HasMaxLength(200);
        builder.Property(e => e.CorrelationId).HasColumnName("correlation_id").HasMaxLength(100);
        builder.Property(e => e.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("NOW()");

        // Indexes
        builder.HasIndex(e => e.UserId).HasDatabaseName("idx_auth_audit_logs_user_id");
        builder.HasIndex(e => e.CreatedAt).HasDatabaseName("idx_auth_audit_logs_created_at");
        builder.HasIndex(e => e.CorrelationId).HasDatabaseName("idx_auth_audit_logs_correlation_id");
        builder.HasIndex(e => new { e.Action, e.Success }).HasDatabaseName("idx_auth_audit_logs_action_success");
    }
}
