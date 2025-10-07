namespace Maliev.AuthService.Api.Models.Request;

/// <summary>
/// Request model for validating access token.
/// </summary>
public class ValidateRequest
{
    /// <summary>
    /// Access token to validate
    /// </summary>
    public string AccessToken { get; set; } = string.Empty;
}
