using Maliev.AuthService.Application.DTOs.IAM;

namespace Maliev.AuthService.Application.Interfaces;

/// <summary>
/// Client for communicating with the IAM service for permission and role resolution.
/// </summary>
public interface IIAMServiceClient
{
    /// <summary>
    /// Resolves permissions and roles for a specified principal.
    /// </summary>
    /// <param name="principalId">The principal identifier.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A response containing resolved permissions and roles.</returns>
    Task<PermissionResolutionResponse> ResolvePermissionsAsync(
        Guid principalId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Grants a role to a specified principal synchronously.
    /// Used by AuthService to grant Platform Owner role to the first @maliev.com employee
    /// during auto-provisioning, before issuing the JWT.
    /// </summary>
    /// <param name="principalId">The principal identifier.</param>
    /// <param name="roleId">The role identifier to grant.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    Task GrantRoleAsync(
        Guid principalId,
        string roleId,
        CancellationToken cancellationToken = default);
}
