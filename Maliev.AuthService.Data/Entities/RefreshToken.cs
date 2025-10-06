namespace Maliev.AuthService.Data.Entities;

/// <summary>
/// Represents a refresh token stored in the database.
/// Refresh tokens are hashed using SHA-256 before storage.
/// </summary>
public class RefreshToken
{
    /// <summary>
    /// Unique identifier for the refresh token record
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// SHA-256 hash of the actual refresh token value.
    /// The plaintext token is never stored.
    /// </summary>
    public required string TokenHash { get; set; }

    /// <summary>
    /// The user ID this token belongs to
    /// </summary>
    public required string UserId { get; set; }

    /// <summary>
    /// The type of user (Customer or Employee)
    /// </summary>
    public UserType UserType { get; set; }

    /// <summary>
    /// The token family ID - all tokens from the same login session share this ID
    /// </summary>
    public Guid FamilyId { get; set; }

    /// <summary>
    /// When the token was created
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// When the token expires
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Whether the token has been explicitly revoked
    /// </summary>
    public bool IsRevoked { get; set; }

    /// <summary>
    /// Whether the token has been used for a refresh operation
    /// </summary>
    public bool IsUsed { get; set; }

    /// <summary>
    /// When the token was revoked (if applicable)
    /// </summary>
    public DateTime? RevokedAt { get; set; }

    /// <summary>
    /// Concurrency token for optimistic concurrency control
    /// </summary>
    public byte[] Version { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Navigation property to the token family
    /// </summary>
    public TokenFamily? TokenFamily { get; set; }
}
