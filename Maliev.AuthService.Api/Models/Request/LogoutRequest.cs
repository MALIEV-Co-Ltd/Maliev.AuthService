namespace Maliev.AuthService.Api.Models.Request;

/// <summary>
/// Request model for user logout.
/// </summary>
public class LogoutRequest
{
    /// <summary>
    /// Refresh token to invalidate
    /// </summary>
    public string RefreshToken { get; set; } = string.Empty;
}
