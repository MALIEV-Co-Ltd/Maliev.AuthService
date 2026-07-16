namespace Maliev.AuthService.Application.DTOs.Response;

/// <summary>Returns service identity metadata and, once, a newly generated secret.</summary>
public sealed record ServiceIdentityResponse
{
    /// <summary>Gets the canonical workload identifier.</summary>
    public required string WorkloadId { get; init; }

    /// <summary>Gets the stable client identifier.</summary>
    public required string ClientId { get; init; }

    /// <summary>Gets the IAM principal identifier.</summary>
    public required Guid PrincipalId { get; init; }

    /// <summary>Gets the IAM access profile version.</summary>
    public required int ProfileVersion { get; init; }

    /// <summary>Gets the exact least-privilege IAM role identifier.</summary>
    public required string RoleId { get; init; }

    /// <summary>Gets whether the logical identity is active.</summary>
    public required bool IsActive { get; init; }

    /// <summary>Gets the current secret version number.</summary>
    public required int CredentialVersion { get; init; }

    /// <summary>Gets the one-time plaintext secret on the first successful create or rotation response only.</summary>
    public string? ClientSecret { get; init; }

    /// <summary>Gets whether plaintext secret retrieval is available on this response.</summary>
    public required bool SecretRetrievable { get; init; }

    /// <summary>Gets the hard expiry of the current credential.</summary>
    public required DateTimeOffset HardExpiresAt { get; init; }
}
