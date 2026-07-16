using Maliev.AuthService.Application.DTOs.IAM;

namespace Maliev.AuthService.Application.Interfaces;

/// <summary>Calls IAM workload provisioning using the original employee authorization.</summary>
public interface IWorkloadIdentityIamClient
{
    /// <summary>Creates or reconciles an authoritative IAM workload principal.</summary>
    Task<WorkloadPrincipalResponse> ProvisionAsync(
        string workloadId,
        ProvisionWorkloadPrincipalRequest request,
        string callerBearerToken,
        CancellationToken cancellationToken = default);
}
