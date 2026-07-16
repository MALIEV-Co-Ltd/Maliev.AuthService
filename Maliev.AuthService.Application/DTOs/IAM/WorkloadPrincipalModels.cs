using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Application.DTOs.IAM;

/// <summary>Requests an idempotent server-owned IAM workload profile.</summary>
public sealed record ProvisionWorkloadPrincipalRequest
{
    /// <summary>Gets the profile version.</summary>
    [Range(1, int.MaxValue)]
    public required int ProfileVersion { get; init; }

    /// <summary>Gets the shared saga operation identifier.</summary>
    public required Guid OperationId { get; init; }
}

/// <summary>Describes IAM's authoritative workload binding.</summary>
public sealed record WorkloadPrincipalResponse
{
    /// <summary>Gets the canonical workload identifier.</summary>
    public required string WorkloadId { get; init; }

    /// <summary>Gets the IAM principal identifier.</summary>
    public required Guid PrincipalId { get; init; }

    /// <summary>Gets the applied profile version.</summary>
    public required int ProfileVersion { get; init; }

    /// <summary>Gets the exact role identifier.</summary>
    public required string RoleId { get; init; }
}
