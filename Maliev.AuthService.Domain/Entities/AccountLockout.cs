namespace Maliev.AuthService.Domain.Entities;

/// <summary>
/// Tracks failed login attempts and lockout state per user account.
/// </summary>
public class AccountLockout
{
    /// <summary>
    /// Unique record identifier (Primary Key)
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// User identifier
    /// </summary>
    public Guid UserId { get; set; }

    /// <summary>
    /// User type (customer or employee)
    /// </summary>
    public UserType UserType { get; set; }

    /// <summary>
    /// Number of consecutive failed attempts (0-5)
    /// </summary>
    public int FailedAttempts { get; set; }

    /// <summary>
    /// Lockout expiration (15 min from 5th failure)
    /// </summary>
    public DateTime? LockedUntil { get; set; }

    /// <summary>
    /// Last authentication attempt timestamp
    /// </summary>
    public DateTime LastAttemptAt { get; set; }

    /// <summary>
    /// Record creation timestamp
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Last update timestamp
    /// </summary>
    public DateTime UpdatedAt { get; set; }
}
