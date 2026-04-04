using System.Text.Json.Serialization;

namespace Maliev.AuthService.Application.DTOs.Response;

/// <summary>
/// Response model for successful login.
/// </summary>
public class LoginResponse
{
    /// <summary>
    /// JWT access token (2 hours expiry).
    /// </summary>
    public string AccessToken { get; set; } = string.Empty;

    /// <summary>
    /// Refresh token (7 days expiry). Null for service logins.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RefreshToken { get; set; }

    /// <summary>
    /// Token type (always "Bearer").
    /// </summary>
    public string TokenType { get; set; } = "Bearer";

    /// <summary>
    /// Access token expiration in seconds (7200 = 2 hours).
    /// </summary>
    public int ExpiresIn { get; set; } = 7200;

    /// <summary>
    /// User identity information.
    /// </summary>
    public UserIdentityResponse User { get; set; } = null!;
}

/// <summary>
/// User identity information in login response.
/// </summary>
public class UserIdentityResponse
{
    /// <summary>
    /// User unique identifier.
    /// </summary>
    public string UserId { get; set; } = string.Empty;

    /// <summary>
    /// User type: "customer" or "employee".
    /// </summary>
    public string UserType { get; set; } = string.Empty;

    /// <summary>
    /// User email address.
    /// </summary>
    public string? Email { get; set; }

    /// <summary>
    /// User full name.
    /// </summary>
    public string? Name { get; set; }
}
