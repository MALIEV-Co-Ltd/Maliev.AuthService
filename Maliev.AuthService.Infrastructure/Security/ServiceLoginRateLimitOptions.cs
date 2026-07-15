using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Infrastructure.Security;

/// <summary>
/// Bounded distributed service-login rate-limit settings.
/// </summary>
public sealed class ServiceLoginRateLimitOptions
{
    /// <summary>Gets or sets permits per window for one socket peer.</summary>
    [Range(1, 1000)]
    public int PeerPermitLimit { get; set; } = 100;

    /// <summary>Gets or sets permits per window for one normalized client identifier.</summary>
    [Range(1, 1000)]
    public int ClientPermitLimit { get; set; } = 100;

    /// <summary>Gets or sets the fixed window duration in seconds.</summary>
    [Range(1, 3600)]
    public int WindowSeconds { get; set; } = 60;
}
