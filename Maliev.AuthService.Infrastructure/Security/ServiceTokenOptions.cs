using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Infrastructure.Security;

/// <summary>
/// Bounded lifetime settings for service access tokens.
/// </summary>
public sealed class ServiceTokenOptions
{
    /// <summary>
    /// Gets or sets the service access-token lifetime in seconds.
    /// </summary>
    [Range(60, 3600)]
    public int ServiceTokenExpirationInSeconds { get; set; } = 900;
}
