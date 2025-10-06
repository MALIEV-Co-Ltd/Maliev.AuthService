using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Maliev.AuthService.Api.Models;

/// <summary>
/// Request model for POST /auth/refresh endpoint.
/// </summary>
public class RefreshRequest
{
    /// <summary>
    /// Refresh token obtained from login or previous refresh.
    /// </summary>
    [Required(ErrorMessage = "Refresh token is required")]
    [JsonPropertyName("refresh_token")]
    public required string RefreshToken { get; set; }
}
