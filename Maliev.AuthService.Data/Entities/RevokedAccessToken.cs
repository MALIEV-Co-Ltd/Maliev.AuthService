namespace Maliev.AuthService.Data.Entities;

/// <summary>
/// Represents a revoked access token.
/// Access tokens are revoked before expiration when user logs out, password changes, or security events occur.
/// </summary>
public class RevokedAccessToken
{
    /// <summary>
    /// The JWT ID (jti claim) of the revoked access token
    /// </summary>
    public required string Jti { get; set; }

    /// <summary>
    /// When the token was revoked
    /// </summary>
    public DateTime RevokedAt { get; set; }

    /// <summary>
    /// When the token originally expires.
    /// Used for cleanup - revoked tokens can be deleted after expiration.
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Reason for revocation (e.g., "user_logout", "password_change", "security_event")
    /// </summary>
    public string? Reason { get; set; }
}
