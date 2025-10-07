namespace Maliev.AuthService.Data.Entities;

/// <summary>
/// Tracks failed authentication attempts per IP address for distributed brute force protection.
/// </summary>
public class IpRateLimit
{
    /// <summary>
    /// Unique record identifier (Primary Key)
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// IPv4 or IPv6 address
    /// </summary>
    public string IpAddress { get; set; } = string.Empty;

    /// <summary>
    /// Failed attempts in current 15-minute window (0-20)
    /// </summary>
    public int FailedAttempts { get; set; }

    /// <summary>
    /// IP block expiration (15 min from 20th failure)
    /// </summary>
    public DateTime? BlockedUntil { get; set; }

    /// <summary>
    /// Start of current 15-minute window
    /// </summary>
    public DateTime WindowStart { get; set; }

    /// <summary>
    /// Record creation timestamp
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Last update timestamp
    /// </summary>
    public DateTime UpdatedAt { get; set; }

    /// <summary>
    /// Row version for optimistic concurrency control
    /// </summary>
    public byte[] Version { get; set; } = Array.Empty<byte>();
}
