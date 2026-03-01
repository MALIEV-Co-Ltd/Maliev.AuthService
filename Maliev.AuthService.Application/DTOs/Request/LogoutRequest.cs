using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Application.DTOs.Request;

/// <summary>
/// Request model for user logout.
/// </summary>
public class LogoutRequest
{
    /// <summary>
    /// Refresh token to invalidate.
    /// </summary>
    [Required]
    public string RefreshToken { get; set; } = string.Empty;
}
