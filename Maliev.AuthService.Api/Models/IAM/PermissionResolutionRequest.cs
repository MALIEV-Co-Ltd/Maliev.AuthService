namespace Maliev.AuthService.Api.Models.IAM;

/// <summary>
/// Request model for resolving permissions and roles from the IAM service.
/// Must match IAMService's ResolvePermissionsRequest contract.
/// </summary>
public record PermissionResolutionRequest
{
    /// <summary>
    /// The principal identifier (must be string to match IAMService contract).
    /// </summary>
    public required string PrincipalId { get; init; }

    /// <summary>
    /// Hierarchical resource path (e.g., "projects/123/datasets/456")
    /// </summary>
    public string? ResourcePath { get; init; }

    /// <summary>
    /// Request timestamp (for condition evaluation)
    /// </summary>
    public DateTime? RequestTime { get; init; }

    /// <summary>
    /// Request IP address (for condition evaluation)
    /// </summary>
    public string? RequestIp { get; init; }
}
