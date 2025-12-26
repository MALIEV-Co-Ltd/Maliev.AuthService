namespace Maliev.AuthService.Api.Models.IAM;

/// <summary>
/// Response model for permission and role resolution.
/// </summary>
public record PermissionResolutionResponse
{
    /// <summary>
    /// The principal identifier.
    /// </summary>
    public Guid PrincipalId { get; init; }

    /// <summary>
    /// List of resolved permissions.
    /// </summary>
    public List<string> Permissions { get; init; } = new();

    /// <summary>
    /// List of resolved roles.
    /// </summary>
    public List<string> Roles { get; init; } = new();

    /// <summary>
    /// Timestamp when resolution occurred.
    /// </summary>
    public DateTime ResolvedAt { get; init; }

    /// <summary>
    /// Optional hint for how long this resolution can be cached.
    /// </summary>
    public DateTime? CacheUntil { get; init; }
}
