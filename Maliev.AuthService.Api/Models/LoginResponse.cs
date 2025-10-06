using System.Text.Json.Serialization;

namespace Maliev.AuthService.Api.Models;

/// <summary>
/// Response model for successful login or refresh operations.
/// </summary>
public class LoginResponse
{
    /// <summary>
    /// JWT access token.
    /// </summary>
    [JsonPropertyName("access_token")]
    public required string AccessToken { get; set; }

    /// <summary>
    /// Refresh token for obtaining new access tokens.
    /// </summary>
    [JsonPropertyName("refresh_token")]
    public required string RefreshToken { get; set; }

    /// <summary>
    /// Token type. Always "Bearer".
    /// </summary>
    [JsonPropertyName("token_type")]
    public string TokenType => "Bearer";

    /// <summary>
    /// Access token lifetime in seconds.
    /// </summary>
    [JsonPropertyName("expires_in")]
    public required int ExpiresIn { get; set; }
}
