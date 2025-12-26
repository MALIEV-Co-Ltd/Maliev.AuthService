using Maliev.AuthService.Api.Models.IAM;

namespace Maliev.AuthService.Api.Services;

/// <summary>
/// Client for communicating with the IAM service for permission and role resolution.
/// </summary>
public interface IIAMClient
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
}
