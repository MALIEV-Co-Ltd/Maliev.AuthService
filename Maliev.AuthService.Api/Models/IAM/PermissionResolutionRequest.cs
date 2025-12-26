namespace Maliev.AuthService.Api.Models.IAM;

/// <summary>
/// Request model for resolving permissions and roles from the IAM service.
/// </summary>
public record PermissionResolutionRequest
{
    /// <summary>
    /// The principal identifier for which to resolve permissions.
    /// </summary>
    public Guid PrincipalId { get; init; }

    /// <summary>
    /// Whether to include resource-scoped permissions.
    /// </summary>
    public bool IncludeResourceScoped { get; init; } = false;
}
