namespace Maliev.AuthService.Domain.Entities;

/// <summary>
/// Represents an email verification token for the email verification flow.
/// </summary>
public class VerificationToken
{
    /// <summary>
    /// Unique token identifier (Primary Key).
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Principal identifier this token belongs to.
    /// </summary>
    public Guid PrincipalId { get; set; }

    /// <summary>
    /// SHA-256 hash of the verification token (64 characters hex).
    /// </summary>
    public string TokenHash { get; set; } = string.Empty;

    /// <summary>
    /// Email address this token was issued for.
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Token expiration timestamp.
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Indicates if the token has been used.
    /// </summary>
    public bool IsUsed { get; set; }

    /// <summary>
    /// When the token was used, or null if not yet used.
    /// </summary>
    public DateTime? UsedAt { get; set; }

    /// <summary>
    /// Token creation timestamp.
    /// </summary>
    public DateTime CreatedAt { get; set; }
}
