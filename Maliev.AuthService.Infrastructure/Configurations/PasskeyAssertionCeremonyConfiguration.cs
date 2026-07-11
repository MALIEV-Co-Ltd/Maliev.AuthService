using Maliev.AuthService.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Infrastructure.Configurations;

/// <summary>
/// Configures short-lived passkey assertion ceremonies.
/// </summary>
public sealed class PasskeyAssertionCeremonyConfiguration : IEntityTypeConfiguration<PasskeyAssertionCeremony>
{
    /// <inheritdoc />
    public void Configure(EntityTypeBuilder<PasskeyAssertionCeremony> builder)
    {
        builder.ToTable("passkey_assertion_ceremonies");
        builder.HasKey(ceremony => ceremony.Id);
        builder.Property(ceremony => ceremony.FlowIdHash).HasMaxLength(64).IsRequired();
        builder.Property(ceremony => ceremony.ChallengeHash).HasMaxLength(64).IsRequired();
        builder.Property(ceremony => ceremony.AssertionOptionsJson).HasColumnType("jsonb").IsRequired();
        builder.Property(ceremony => ceremony.ServiceName).HasMaxLength(128).IsRequired();
        builder.Property(ceremony => ceremony.Application).HasMaxLength(64).IsRequired();
        builder.Property(ceremony => ceremony.ExpectedUserType)
            .HasColumnName("expected_user_type")
            .IsRequired();
        builder.Property(ceremony => ceremony.CreatedAtUtc).IsRequired();
        builder.Property(ceremony => ceremony.ExpiresAtUtc).IsRequired();
        builder.HasIndex(ceremony => ceremony.FlowIdHash).IsUnique();
        builder.HasIndex(ceremony => ceremony.ChallengeHash).IsUnique();
        builder.HasIndex(ceremony => ceremony.ExpiresAtUtc);
        builder.ToTable(table => table.HasCheckConstraint(
            "ck_passkey_assertion_ceremonies_expected_user_type",
            "expected_user_type IN (1, 2)"));
    }
}
