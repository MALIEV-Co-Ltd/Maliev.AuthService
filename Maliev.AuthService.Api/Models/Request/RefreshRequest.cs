namespace Maliev.AuthService.Api.Models.Request;

/// <summary>
/// Request model for refreshing access token.
/// </summary>
public class RefreshRequest
{
    /// <summary>
    /// Refresh token from previous login/refresh response
    /// </summary>
    public string RefreshToken { get; set; } = string.Empty;
}
