namespace Maliev.AuthService.Api.Models.Request;

using System.ComponentModel.DataAnnotations;

/// <summary>
/// Request model for validating access token.
/// </summary>
public class ValidateRequest
{
    /// <summary>
    /// Access token to validate
    /// </summary>
    [Required]
    public string AccessToken { get; set; } = string.Empty;
}
