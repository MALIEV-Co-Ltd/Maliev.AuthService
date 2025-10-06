using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Maliev.AuthService.Api.Models;

/// <summary>
/// Request model for POST /auth/validate endpoint.
/// </summary>
public class ValidateRequest
{
    /// <summary>
    /// JWT access token to validate.
    /// </summary>
    [Required(ErrorMessage = "Access token is required")]
    [JsonPropertyName("access_token")]
    public required string AccessToken { get; set; }
}
