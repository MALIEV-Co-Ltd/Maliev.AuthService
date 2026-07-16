using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Application.DTOs.Request;

/// <summary>Requests idempotent provisioning of a service identity.</summary>
public sealed record ProvisionServiceIdentityRequest
{
    /// <summary>Gets the server-owned IAM access profile version.</summary>
    [Range(1, int.MaxValue)]
    public required int ProfileVersion { get; init; }

    /// <summary>Gets the caller-generated idempotency operation identifier.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Gets the human-readable service name.</summary>
    [Required, StringLength(100, MinimumLength = 1)]
    public required string ServiceName { get; init; }

    /// <summary>Gets the bounded hard credential lifetime in days.</summary>
    [Range(1, 365)]
    public int HardExpiryDays { get; init; } = 90;
}

/// <summary>Requests idempotent service secret rotation.</summary>
public sealed record RotateServiceIdentityRequest
{
    /// <summary>Gets the caller-generated idempotency operation identifier.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Gets the prior-version overlap in seconds.</summary>
    [Range(0, 86_400)]
    public int GracePeriodSeconds { get; init; } = 3_600;

    /// <summary>Gets the bounded hard credential lifetime in days.</summary>
    [Range(1, 365)]
    public int HardExpiryDays { get; init; } = 90;
}

/// <summary>Requests idempotent logical revocation of a service identity.</summary>
public sealed record RevokeServiceIdentityRequest
{
    /// <summary>Gets the caller-generated idempotency operation identifier.</summary>
    public required Guid OperationId { get; init; }
}
