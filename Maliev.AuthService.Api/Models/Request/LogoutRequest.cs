namespace Maliev.AuthService.Api.Models.Request;

using System.ComponentModel.DataAnnotations;

/// <summary>
/// Request model for user logout.
/// </summary>
public class LogoutRequest
{
    /// <summary>
    /// Refresh token to invalidate
    /// </summary>
    [Required]
    public string RefreshToken { get; set; } = string.Empty;
}
