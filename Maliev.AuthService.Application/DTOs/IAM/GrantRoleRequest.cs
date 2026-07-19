namespace Maliev.AuthService.Application.DTOs.IAM;

/// <summary>
/// Request model for granting a role to a principal via the IAM service.
/// Must match IAMService's GrantRoleRequest contract.
/// </summary>
public record GrantRoleRequest
{
    /// <summary>
    /// The unique identifier of the role to grant.
    /// </summary>
    public required string RoleId { get; init; }

    /// <summary>
    /// Hierarchical resource path. NULL for global role bindings.
    /// </summary>
    public string? ResourcePath { get; init; }

    /// <summary>
    /// Expiration date and time for the role grant.
    /// </summary>
    public DateTime? ExpiresAt { get; init; }
}
