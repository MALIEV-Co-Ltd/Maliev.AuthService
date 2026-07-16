namespace Maliev.AuthService.Domain.Entities;

/// <summary>
/// Describes the lifecycle state of a hashed service credential version.
/// </summary>
public enum ServiceCredentialVersionStatus
{
    /// <summary>The hash is staged but cannot authenticate.</summary>
    Pending = 0,

    /// <summary>The version is the primary active credential.</summary>
    Active = 1,

    /// <summary>The version is accepted during a bounded rotation overlap.</summary>
    Grace = 2,

    /// <summary>The version can no longer authenticate.</summary>
    Revoked = 3
}

/// <summary>
/// Stores one immutable hashed secret version for a logical service credential.
/// </summary>
public sealed class ServiceCredentialVersion
{
    /// <summary>Gets or sets the version identifier.</summary>
    public Guid Id { get; set; }

    /// <summary>Gets or sets the owning logical credential identifier.</summary>
    public Guid ServiceCredentialId { get; set; }

    /// <summary>Gets or sets the monotonically increasing version number.</summary>
    public int Version { get; set; }

    /// <summary>Gets or sets the SHA-256 hash of a uniformly random 256-bit secret.</summary>
    public string SecretHash { get; set; } = string.Empty;

    /// <summary>Gets or sets the lifecycle status.</summary>
    public ServiceCredentialVersionStatus Status { get; set; }

    /// <summary>Gets or sets the creation timestamp.</summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Gets or sets the activation timestamp.</summary>
    public DateTimeOffset? ActivatedAt { get; set; }

    /// <summary>Gets or sets the optional grace-period end.</summary>
    public DateTimeOffset? GraceExpiresAt { get; set; }

    /// <summary>Gets or sets the hard expiry after which this version is always rejected.</summary>
    public DateTimeOffset HardExpiresAt { get; set; }

    /// <summary>Gets or sets the revocation timestamp.</summary>
    public DateTimeOffset? RevokedAt { get; set; }

    /// <summary>Gets or sets the owning logical credential.</summary>
    public ServiceCredential ServiceCredential { get; set; } = null!;

    /// <summary>Returns whether the version is accepted at the supplied instant.</summary>
    public bool CanAuthenticate(DateTimeOffset now) =>
        now < HardExpiresAt &&
        Status is ServiceCredentialVersionStatus.Active or ServiceCredentialVersionStatus.Grace &&
        (Status != ServiceCredentialVersionStatus.Grace ||
            GraceExpiresAt.HasValue && now < GraceExpiresAt.Value);
}
