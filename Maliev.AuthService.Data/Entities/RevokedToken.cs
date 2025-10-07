namespace Maliev.AuthService.Data.Entities;

/// <summary>
/// Represents a revoked access token for distributed validation (supports <2s propagation via Redis + DB fallback).
/// </summary>
public class RevokedToken
{
    /// <summary>
    /// Unique record identifier (Primary Key)
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// JWT ID claim from token (unique identifier)
    /// </summary>
    public string Jti { get; set; } = string.Empty;

    /// <summary>
    /// User whose token was revoked
    /// </summary>
    public Guid UserId { get; set; }

    /// <summary>
    /// User type (customer, employee, or service)
    /// </summary>
    public UserType UserType { get; set; }

    /// <summary>
    /// When token was revoked
    /// </summary>
    public DateTime RevokedAt { get; set; }

    /// <summary>
    /// Token expiration (for cleanup)
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Revocation reason: logout, password_change, account_disabled, admin_action, reuse_detected
    /// </summary>
    public string Reason { get; set; } = string.Empty;
}
