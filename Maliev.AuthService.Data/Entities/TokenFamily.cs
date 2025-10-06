namespace Maliev.AuthService.Data.Entities;

/// <summary>
/// Represents a token family - a lineage of refresh tokens from the same login session.
/// Used to detect token reuse attacks.
/// </summary>
public class TokenFamily
{
    /// <summary>
    /// Unique identifier for the token family
    /// </summary>
    public Guid FamilyId { get; set; }

    /// <summary>
    /// The user ID this family belongs to
    /// </summary>
    public required string UserId { get; set; }

    /// <summary>
    /// The type of user (Customer or Employee)
    /// </summary>
    public UserType UserType { get; set; }

    /// <summary>
    /// When the token family was created (initial login)
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// When the most recent token in this family was used
    /// </summary>
    public DateTime LastUsedAt { get; set; }

    /// <summary>
    /// Navigation property to all refresh tokens in this family
    /// </summary>
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}
