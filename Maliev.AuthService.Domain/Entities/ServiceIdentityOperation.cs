namespace Maliev.AuthService.Domain.Entities;

/// <summary>Identifies the durable operation type for a service identity.</summary>
public enum ServiceIdentityOperationKind
{
    /// <summary>Initial identity provisioning.</summary>
    Provision = 0,

    /// <summary>Credential secret rotation.</summary>
    Rotate = 1,

    /// <summary>Logical identity revocation.</summary>
    Revoke = 2
}

/// <summary>Identifies progress through the durable provisioning saga.</summary>
public enum ServiceIdentityOperationState
{
    /// <summary>The idempotency record is persisted.</summary>
    Started = 0,

    /// <summary>IAM returned an exact verified workload binding.</summary>
    IamReady = 1,

    /// <summary>The credential and audit mutation committed atomically.</summary>
    CredentialCommitted = 2,

    /// <summary>The operation completed successfully.</summary>
    Completed = 3
}

/// <summary>
/// Durable idempotency and recovery record for service identity lifecycle operations.
/// </summary>
public sealed class ServiceIdentityOperation
{
    /// <summary>Gets or sets the caller-generated operation identifier.</summary>
    public Guid Id { get; set; }

    /// <summary>Gets or sets the canonical workload identifier.</summary>
    public string WorkloadId { get; set; } = string.Empty;

    /// <summary>Gets or sets the operation kind.</summary>
    public ServiceIdentityOperationKind Kind { get; set; }

    /// <summary>Gets or sets the SHA-256 hash of the canonical request.</summary>
    public string RequestHash { get; set; } = string.Empty;

    /// <summary>Gets or sets the employee actor subject.</summary>
    public Guid ActorId { get; set; }

    /// <summary>Gets or sets current saga state.</summary>
    public ServiceIdentityOperationState State { get; set; }

    /// <summary>Gets or sets the verified IAM principal identifier.</summary>
    public Guid? IamPrincipalId { get; set; }

    /// <summary>Gets or sets the verified IAM profile version.</summary>
    public int? IamProfileVersion { get; set; }

    /// <summary>Gets or sets the verified IAM role identifier.</summary>
    public string? IamRoleId { get; set; }

    /// <summary>Gets or sets the committed credential version identifier.</summary>
    public Guid? CredentialVersionId { get; set; }

    /// <summary>Gets or sets creation time.</summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Gets or sets last update time.</summary>
    public DateTimeOffset UpdatedAt { get; set; }
}
