namespace Maliev.AuthService.Application.DTOs.Response;

/// <summary>
/// Represents the result of an authentication attempt, including success status,
/// response data on success, and error details on failure.
/// </summary>
public class AuthenticationResult
{
    /// <summary>
    /// Gets or sets a value indicating whether the authentication was successful.
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Gets or sets the authentication response on success.
    /// </summary>
    public LoginResponse? Response { get; set; }

    /// <summary>
    /// Gets or sets the error code on failure (e.g., "invalid_credentials", "account_locked").
    /// </summary>
    public string? ErrorCode { get; set; }

    /// <summary>
    /// Gets or sets the detailed error description on failure.
    /// </summary>
    public string? ErrorDescription { get; set; }

    /// <summary>
    /// Gets or sets the date and time until which the account is locked.
    /// </summary>
    public DateTime? LockedUntil { get; set; }

    /// <summary>
    /// Gets or sets the date and time after which a request can be retried.
    /// </summary>
    public DateTime? RetryAfter { get; set; }

    /// <summary>
    /// Gets or sets the principal identifier resolved during authentication.
    /// </summary>
    public Guid? PrincipalId { get; set; }
}
