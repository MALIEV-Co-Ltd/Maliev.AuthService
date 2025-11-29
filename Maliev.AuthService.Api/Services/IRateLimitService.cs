namespace Maliev.AuthService.Api.Services;
/// <summary>
/// Service interface for RateLimit operations
/// </summary>

public interface IRateLimitService
{
    /// <summary>
    /// Checks if rate limit is exceeded for an IP address
    /// </summary>
    /// <param name="ipAddress">The IP address to check</param>
    /// <returns>True if rate limit is exceeded, otherwise false</returns>
    Task<bool> IsRateLimitExceededAsync(string ipAddress);

    /// <summary>
    /// Records a failed authentication attempt for an IP address
    /// </summary>
    /// <param name="ipAddress">The IP address</param>
    /// <returns>A task representing the asynchronous operation</returns>
    Task RecordFailedAttemptAsync(string ipAddress);

    /// <summary>
    /// Gets the date and time until which the IP address is blocked
    /// </summary>
    /// <param name="ipAddress">The IP address</param>
    /// <returns>The block expiration date, or null if not blocked</returns>
    Task<DateTime?> GetBlockedUntilAsync(string ipAddress);
}
