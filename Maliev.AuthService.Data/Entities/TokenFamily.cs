namespace Maliev.AuthService.Data.Entities;

/// <summary>
/// Tracks lineage of refresh tokens for detecting reuse across multiple refresh cycles.
/// </summary>
public class TokenFamily
{
    /// <summary>
    /// Unique family identifier (Primary Key)
    /// </summary>
    public Guid FamilyId { get; set; }

    /// <summary>
    /// User who owns this token family
    /// </summary>
    public Guid UserId { get; set; }

    /// <summary>
    /// User type (customer or employee)
    /// </summary>
    public UserType UserType { get; set; }

    /// <summary>
    /// When family was created (initial login)
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Last time any token in family was refreshed
    /// </summary>
    public DateTime LastRefreshAt { get; set; }

    // Navigation property
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}
