using Maliev.AuthService.Data.Entities;

namespace Maliev.AuthService.Api.Services;
/// <summary>
/// Service interface for AccountLockout operations
/// </summary>

public interface IAccountLockoutService
{
    /// <summary>
    /// Checks if an account is currently locked
    /// </summary>
    /// <param name="userId">The user identifier</param>
    /// <param name="userType">The type of user</param>
    /// <returns>True if the account is locked, otherwise false</returns>
    Task<bool> IsAccountLockedAsync(Guid userId, UserType userType);

    /// <summary>
    /// Records a failed login attempt for an account
    /// </summary>
    /// <param name="userId">The user identifier</param>
    /// <param name="userType">The type of user</param>
    /// <returns>A task representing the asynchronous operation</returns>
    Task RecordFailedAttemptAsync(Guid userId, UserType userType);

    /// <summary>
    /// Resets the failed login attempts for an account
    /// </summary>
    /// <param name="userId">The user identifier</param>
    /// <param name="userType">The type of user</param>
    /// <returns>A task representing the asynchronous operation</returns>
    Task ResetFailedAttemptsAsync(Guid userId, UserType userType);

    /// <summary>
    /// Gets the date and time until which the account is locked
    /// </summary>
    /// <param name="userId">The user identifier</param>
    /// <param name="userType">The type of user</param>
    /// <returns>The lock expiration date, or null if not locked</returns>
    Task<DateTime?> GetLockedUntilAsync(Guid userId, UserType userType);
}
