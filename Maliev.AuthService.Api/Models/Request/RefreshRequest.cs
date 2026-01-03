namespace Maliev.AuthService.Api.Models.Request;

using System.ComponentModel.DataAnnotations;

/// <summary>
/// Request model for refreshing access token.
/// </summary>
public class RefreshRequest
{
    /// <summary>
    /// Refresh token from previous login/refresh response
    /// </summary>
    [Required]
    public string RefreshToken { get; set; } = string.Empty;
}
