namespace Maliev.AuthService.Api.Models.Response;

/// <summary>
/// Response model for token validation.
/// </summary>
public class ValidateResponse
{
    /// <summary>
    /// Whether the token is valid
    /// </summary>
    public bool Valid { get; set; }

    /// <summary>
    /// User ID if token is valid
    /// </summary>
    public string? UserId { get; set; }

    /// <summary>
    /// User type if token is valid
    /// </summary>
    public string? UserType { get; set; }

    /// <summary>
    /// Error description if token is invalid
    /// </summary>
    public string? Error { get; set; }
}
