using Maliev.AuthService.Application.DTOs.IAM;

namespace Maliev.AuthService.Application.Interfaces;

/// <summary>Resolves service-login authority through IAM's isolated token-issuance capability boundary.</summary>
public interface ITokenIssuancePermissionClient
{
    /// <summary>Resolves current permissions and roles for the target service principal.</summary>
    /// <param name="principalId">The exact IAM principal bound into the capability and request.</param>
    /// <param name="cancellationToken">The caller cancellation token.</param>
    /// <returns>The authoritative IAM permission-resolution response.</returns>
    Task<PermissionResolutionResponse> ResolvePermissionsAsync(
        Guid principalId,
        CancellationToken cancellationToken);
}
