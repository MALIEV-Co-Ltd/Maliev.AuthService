using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Application.DTOs.Request;

/// <summary>
/// Request model for revoking access token.
/// </summary>
public class RevokeRequest
{
    /// <summary>
    /// Access token to revoke.
    /// </summary>
    [Required]
    public string Token { get; set; } = string.Empty;

    /// <summary>
    /// Reason for revocation (optional).
    /// </summary>
    public string? Reason { get; set; }
}
