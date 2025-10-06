using System.Text.Json.Serialization;

namespace Maliev.AuthService.Api.Models;

/// <summary>
/// Response model for successful token validation.
/// Contains user identity information extracted from the JWT.
/// </summary>
public class ValidateResponse
{
    /// <summary>
    /// User ID (subject claim from JWT).
    /// </summary>
    [JsonPropertyName("user_id")]
    public required string UserId { get; set; }

    /// <summary>
    /// User type: "customer" or "employee".
    /// </summary>
    [JsonPropertyName("user_type")]
    public required string UserType { get; set; }

    /// <summary>
    /// Username/email.
    /// </summary>
    [JsonPropertyName("username")]
    public required string Username { get; set; }

    /// <summary>
    /// User email address.
    /// </summary>
    [JsonPropertyName("email")]
    public required string Email { get; set; }

    /// <summary>
    /// User roles from JWT claims.
    /// </summary>
    [JsonPropertyName("roles")]
    public required string[] Roles { get; set; }

    /// <summary>
    /// User permissions from JWT claims.
    /// </summary>
    [JsonPropertyName("permissions")]
    public required string[] Permissions { get; set; }
}
