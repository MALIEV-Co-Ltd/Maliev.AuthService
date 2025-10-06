using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Maliev.AuthService.Api.Models;

/// <summary>
/// Request model for POST /auth/revoke endpoint.
/// </summary>
public class RevokeRequest
{
    /// <summary>
    /// JWT access token to revoke.
    /// </summary>
    [Required(ErrorMessage = "Access token is required")]
    [JsonPropertyName("access_token")]
    public required string AccessToken { get; set; }

    /// <summary>
    /// Optional reason for revocation (e.g., "user_logout", "admin_action").
    /// </summary>
    [JsonPropertyName("reason")]
    public string? Reason { get; set; }
}
