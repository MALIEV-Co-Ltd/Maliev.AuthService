namespace Maliev.AuthService.Api.Models.Request;

/// <summary>
/// Request model for user login (customer or employee).
/// </summary>
public class LoginRequest
{
    /// <summary>
    /// Username or email address
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// User password
    /// </summary>
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// User type: "customer" or "employee"
    /// </summary>
    public string UserType { get; set; } = string.Empty;
}
