namespace Maliev.AuthService.Application.DTOs.Request;

/// <summary>
/// Request model for exchanging a Google OAuth token for a Maliev JWT.
/// </summary>
public class GoogleExchangeRequest
{
    /// <summary>
    /// Gets or sets the employee's work email address.
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the employee's full name from Google.
    /// </summary>
    public string? FullName { get; set; }
}
