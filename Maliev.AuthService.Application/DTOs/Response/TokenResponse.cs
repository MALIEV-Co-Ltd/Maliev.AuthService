namespace Maliev.AuthService.Application.DTOs.Response;

/// <summary>
/// Response model for token refresh.
/// </summary>
public class TokenResponse
{
    /// <summary>
    /// JWT access token.
    /// </summary>
    public string AccessToken { get; set; } = string.Empty;

    /// <summary>
    /// New refresh token (rotated).
    /// </summary>
    public string RefreshToken { get; set; } = string.Empty;

    /// <summary>
    /// Token type (always "Bearer").
    /// </summary>
    public string TokenType { get; set; } = "Bearer";

    /// <summary>
    /// Access token expiration in seconds.
    /// </summary>
    public int ExpiresIn { get; set; } = 900;
}
