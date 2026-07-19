namespace Maliev.AuthService.Domain.Entities;

/// <summary>
/// Stores a short-lived hash used to bind a Google credential to one MALIEV browser exchange.
/// </summary>
public sealed class GoogleIdentityNonce
{
    /// <summary>Gets or sets the nonce record identifier.</summary>
    public Guid Id { get; set; }

    /// <summary>Gets or sets the SHA-256 hash of the nonce.</summary>
    public string NonceHash { get; set; } = string.Empty;

    /// <summary>Gets or sets the service caller that requested the nonce.</summary>
    public string ServiceName { get; set; } = string.Empty;

    /// <summary>Gets or sets the normalized MALIEV application selector.</summary>
    public string Application { get; set; } = string.Empty;

    /// <summary>Gets or sets the normalized employee or customer exchange type.</summary>
    public string ExchangeType { get; set; } = string.Empty;

    /// <summary>Gets or sets the UTC expiration timestamp.</summary>
    public DateTime ExpiresAtUtc { get; set; }

    /// <summary>Gets or sets the UTC creation timestamp.</summary>
    public DateTime CreatedAtUtc { get; set; }
}
