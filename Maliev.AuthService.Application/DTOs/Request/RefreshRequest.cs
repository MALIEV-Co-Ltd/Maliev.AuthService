using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Application.DTOs.Request;

/// <summary>
/// Request model for refreshing access token.
/// </summary>
public class RefreshRequest
{
    /// <summary>
    /// Refresh token from previous login/refresh response.
    /// </summary>
    [Required]
    public string RefreshToken { get; set; } = string.Empty;
}
