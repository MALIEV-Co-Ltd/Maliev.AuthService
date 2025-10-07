namespace Maliev.AuthService.Api.Models.Request;

/// <summary>
/// Request model for revoking access token.
/// </summary>
public class RevokeRequest
{
    /// <summary>
    /// Access token to revoke
    /// </summary>
    public string Token { get; set; } = string.Empty;

    /// <summary>
    /// Reason for revocation (optional)
    /// </summary>
    public string? Reason { get; set; }
}
