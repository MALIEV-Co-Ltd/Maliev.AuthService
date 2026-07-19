using System.Net;

namespace Maliev.AuthService.Application.Interfaces;

/// <summary>
/// Applies the shared service credential exchange limit.
/// </summary>
public interface IServiceLoginRateLimiter
{
    /// <summary>
    /// Attempts to acquire one service-login permit.
    /// </summary>
    Task<ServiceLoginRateLimitResult> TryAcquireAsync(
        string clientId,
        IPAddress? remoteIpAddress,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Result of a service-login rate-limit attempt.
/// </summary>
public sealed record ServiceLoginRateLimitResult(
    bool IsAvailable,
    bool IsAllowed,
    int RetryAfterSeconds);
