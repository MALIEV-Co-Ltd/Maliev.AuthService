namespace Maliev.AuthService.Domain.Entities;

/// <summary>
/// Represents a refresh token with family tracking for OAuth 2.0 RFC 9700 rotation and reuse detection.
/// </summary>
public class RefreshToken
{
    /// <summary>
    /// Unique token identifier (Primary Key)
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Links tokens from the same login session for rotation tracking
    /// </summary>
    public Guid FamilyId { get; set; }

    /// <summary>
    /// User identifier from external service (Customer or Employee API)
    /// </summary>
    public Guid UserId { get; set; }

    /// <summary>
    /// Principal identifier from IAM service (universal identity)
    /// Used for permission resolution. May differ from UserId when IAM manages a separate principal.
    /// </summary>
    public Guid PrincipalId { get; set; }

    /// <summary>
    /// Distinguishes customer vs employee users
    /// </summary>
    public UserType UserType { get; set; }

    /// <summary>
    /// SHA-256 hash of the refresh token (64 characters hex)
    /// </summary>
    public string TokenHash { get; set; } = string.Empty;

    /// <summary>
    /// User email address (snapshot at login for refresh tokens)
    /// </summary>
    public string? Email { get; set; }

    /// <summary>
    /// User display name (snapshot at login for refresh tokens)
    /// </summary>
    public string? Name { get; set; }

    /// <summary>
    /// Indicates if token has been used for refresh (reuse detection)
    /// </summary>
    public bool IsUsed { get; set; }

    /// <summary>
    /// When token was used for refresh (audit trail)
    /// </summary>
    public DateTime? UsedAt { get; set; }

    /// <summary>
    /// Token expiration (7 days from creation)
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Token creation timestamp
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// IP address when token was issued (security audit)
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// Row version for optimistic concurrency control
    /// </summary>
    public byte[] Version { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Navigation property to the token family
    /// </summary>
    public TokenFamily Family { get; set; } = null!;
}
