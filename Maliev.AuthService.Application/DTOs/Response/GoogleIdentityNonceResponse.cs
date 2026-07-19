namespace Maliev.AuthService.Application.DTOs.Response;

/// <summary>One-time nonce used to bind a GIS credential to a MALIEV exchange.</summary>
public sealed class GoogleIdentityNonceResponse
{
    /// <summary>Gets or sets the raw nonce supplied to Google Identity Services.</summary>
    public string Nonce { get; set; } = string.Empty;

    /// <summary>Gets or sets the UTC expiration timestamp.</summary>
    public DateTime ExpiresAtUtc { get; set; }
}
