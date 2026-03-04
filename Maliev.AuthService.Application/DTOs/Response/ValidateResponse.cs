namespace Maliev.AuthService.Application.DTOs.Response;

/// <summary>
/// Response model for token validation.
/// </summary>
public class ValidateResponse
{
    /// <summary>
    /// Whether the token is valid.
    /// </summary>
    public bool Valid { get; set; }

    /// <summary>
    /// User ID if token is valid.
    /// </summary>
    public string? UserId { get; set; }

    /// <summary>
    /// User type if token is valid.
    /// </summary>
    public string? UserType { get; set; }

    /// <summary>
    /// User email address if token is valid.
    /// </summary>
    public string? Email { get; set; }

    /// <summary>
    /// User display name if token is valid.
    /// </summary>
    public string? Name { get; set; }

    /// <summary>
    /// List of resolved roles if token is valid.
    /// </summary>
    public List<string> Roles { get; set; } = new();

    /// <summary>
    /// List of resolved permissions if token is valid.
    /// </summary>
    public List<string> Permissions { get; set; } = new();

    /// <summary>
    /// Error description if token is invalid.
    /// </summary>
    public string? Error { get; set; }
}
