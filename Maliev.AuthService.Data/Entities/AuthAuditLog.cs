namespace Maliev.AuthService.Data.Entities;

/// <summary>
/// Immutable audit trail of all authentication events for security monitoring and compliance.
/// </summary>
public class AuthAuditLog
{
    /// <summary>
    /// Unique log entry identifier (Primary Key)
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// User identifier (NULL for failed attempts with invalid username)
    /// </summary>
    public Guid? UserId { get; set; }

    /// <summary>
    /// User type (customer, employee, or service)
    /// </summary>
    public UserType? UserType { get; set; }

    /// <summary>
    /// Action performed: login, refresh, validate, revoke, logout, service_auth
    /// </summary>
    public string Action { get; set; } = string.Empty;

    /// <summary>
    /// Client IP address
    /// </summary>
    public string IpAddress { get; set; } = string.Empty;

    /// <summary>
    /// Client user agent string
    /// </summary>
    public string? UserAgent { get; set; }

    /// <summary>
    /// Whether action succeeded
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Reason for failure (invalid_credentials, account_locked, etc.)
    /// </summary>
    public string? FailureReason { get; set; }

    /// <summary>
    /// Request correlation ID for distributed tracing (RFC 4122 UUID v4)
    /// </summary>
    public string? CorrelationId { get; set; }

    /// <summary>
    /// Log entry timestamp
    /// </summary>
    public DateTime CreatedAt { get; set; }
}
