namespace Maliev.AuthService.Domain.Entities;

/// <summary>
/// Represents a user principal for email verification and identity management.
/// </summary>
public class UserPrincipal
{
    /// <summary>
    /// Unique principal identifier (Primary Key).
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// User email address.
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// User first name.
    /// </summary>
    public string FirstName { get; set; } = string.Empty;

    /// <summary>
    /// User last name.
    /// </summary>
    public string LastName { get; set; } = string.Empty;

    /// <summary>
    /// Type of user (Customer or Employee).
    /// </summary>
    public UserType UserType { get; set; }

    /// <summary>
    /// When the email was verified, or null if not yet verified.
    /// </summary>
    public DateTime? EmailVerifiedAtUtc { get; set; }

    /// <summary>
    /// Record creation timestamp.
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Record last update timestamp.
    /// </summary>
    public DateTime UpdatedAt { get; set; }
}
