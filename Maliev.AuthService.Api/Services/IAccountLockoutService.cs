using Maliev.AuthService.Data.Entities;

namespace Maliev.AuthService.Api.Services;

public interface IAccountLockoutService
{
    Task<bool> IsAccountLockedAsync(Guid userId, UserType userType);
    Task RecordFailedAttemptAsync(Guid userId, UserType userType);
    Task ResetFailedAttemptsAsync(Guid userId, UserType userType);
    Task<DateTime?> GetLockedUntilAsync(Guid userId, UserType userType);
}
