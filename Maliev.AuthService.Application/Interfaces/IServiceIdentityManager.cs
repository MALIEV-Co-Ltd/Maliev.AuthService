using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Application.DTOs.Response;

namespace Maliev.AuthService.Application.Interfaces;

/// <summary>Manages durable service identity credentials.</summary>
public interface IServiceIdentityManager
{
    /// <summary>Provisions a least-privilege service identity.</summary>
    Task<ServiceIdentityResponse> ProvisionAsync(
        string workloadId,
        ProvisionServiceIdentityRequest request,
        Guid actorId,
        string callerBearerToken,
        CancellationToken cancellationToken = default);

    /// <summary>Reads service identity metadata without exposing secret material.</summary>
    Task<ServiceIdentityResponse?> GetAsync(
        string workloadId,
        CancellationToken cancellationToken = default);

    /// <summary>Rotates a service secret with bounded grace.</summary>
    Task<ServiceIdentityResponse> RotateAsync(
        string workloadId,
        RotateServiceIdentityRequest request,
        Guid actorId,
        CancellationToken cancellationToken = default);

    /// <summary>Logically revokes a service identity and every credential version.</summary>
    Task RevokeAsync(
        string workloadId,
        RevokeServiceIdentityRequest request,
        Guid actorId,
        CancellationToken cancellationToken = default);
}
