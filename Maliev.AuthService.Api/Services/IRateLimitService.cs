namespace Maliev.AuthService.Api.Services;

public interface IRateLimitService
{
    Task<bool> IsRateLimitExceededAsync(string ipAddress);
    Task RecordFailedAttemptAsync(string ipAddress);
    Task<DateTime?> GetBlockedUntilAsync(string ipAddress);
}
