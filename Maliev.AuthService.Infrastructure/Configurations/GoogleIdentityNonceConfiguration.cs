using Maliev.AuthService.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Infrastructure.Configurations;

/// <summary>Configures short-lived Google identity nonce records.</summary>
public sealed class GoogleIdentityNonceConfiguration : IEntityTypeConfiguration<GoogleIdentityNonce>
{
    /// <inheritdoc />
    public void Configure(EntityTypeBuilder<GoogleIdentityNonce> builder)
    {
        builder.ToTable("google_identity_nonces");
        builder.HasKey(nonce => nonce.Id);
        builder.Property(nonce => nonce.NonceHash).HasMaxLength(64).IsRequired();
        builder.Property(nonce => nonce.ServiceName).HasMaxLength(128).IsRequired();
        builder.Property(nonce => nonce.Application).HasMaxLength(64).IsRequired();
        builder.Property(nonce => nonce.ExchangeType).HasMaxLength(16).IsRequired();
        builder.Property(nonce => nonce.ExpiresAtUtc).IsRequired();
        builder.Property(nonce => nonce.CreatedAtUtc).IsRequired();
        builder.HasIndex(nonce => nonce.NonceHash).IsUnique();
        builder.HasIndex(nonce => nonce.ExpiresAtUtc);
    }
}
