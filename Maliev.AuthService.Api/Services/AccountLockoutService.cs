using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Data.Entities;
using Maliev.MessagingContracts.Contracts.Auth;
using Maliev.MessagingContracts.Generated;
using MassTransit;
using Microsoft.EntityFrameworkCore;

namespace Maliev.AuthService.Api.Services;
/// <summary>
/// Service for AccountLockout operations
/// </summary>

public class AccountLockoutService : IAccountLockoutService
{
    private readonly AuthDbContext _dbContext;
    private readonly ILogger<AccountLockoutService> _logger;
    private readonly IPublishEndpoint _publishEndpoint;
    private const int MaxFailedAttempts = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);
    /// <summary>
    /// Initializes a new instance of the <see cref="AccountLockoutService"/> class.
    /// </summary>
    /// <param name="dbContext">The database context</param>
    /// <param name="logger">The logger instance</param>
    /// <param name="publishEndpoint">The publish endpoint for events</param>

    public AccountLockoutService(
        AuthDbContext dbContext,
        ILogger<AccountLockoutService> logger,
        IPublishEndpoint publishEndpoint)
    {
        _dbContext = dbContext;
        _logger = logger;
        _publishEndpoint = publishEndpoint;
    }
    /// <inheritdoc/>

    public async Task<bool> IsAccountLockedAsync(Guid userId, UserType userType)
    {
        var lockout = await _dbContext.AccountLockouts
            .FirstOrDefaultAsync(l => l.UserId == userId && l.UserType == userType);

        if (lockout == null)
        {
            return false;
        }

        if (lockout.LockedUntil.HasValue && lockout.LockedUntil.Value > DateTime.UtcNow)
        {
            return true;
        }

        // Lockout expired, reset
        if (lockout.LockedUntil.HasValue && lockout.LockedUntil.Value <= DateTime.UtcNow)
        {
            lockout.FailedAttempts = 0;
            lockout.LockedUntil = null;
            lockout.UpdatedAt = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();
        }

        return false;
    }
    /// <inheritdoc/>

    public async Task RecordFailedAttemptAsync(Guid userId, UserType userType)
    {
        try
        {
            await RecordFailedAttemptInternalAsync(userId, userType);
        }
        catch (DbUpdateException)
        {
            // Handle concurrency/duplicate key race condition
            // If insert failed, it means the record was created by another process/thread
            // Detach only matching AccountLockout entities to avoid losing other pending changes
            var entries = _dbContext.ChangeTracker.Entries<AccountLockout>()
                .Where(e => e.Entity.UserId == userId && e.Entity.UserType == userType)
                .ToList();

            foreach (var entry in entries)
            {
                entry.State = EntityState.Detached;
            }
            await RecordFailedAttemptInternalAsync(userId, userType);
        }
    }

    private async Task RecordFailedAttemptInternalAsync(Guid userId, UserType userType)
    {
        var lockout = await _dbContext.AccountLockouts
            .FirstOrDefaultAsync(l => l.UserId == userId && l.UserType == userType);

        if (lockout == null)
        {
            lockout = new AccountLockout
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                UserType = userType,
                FailedAttempts = 1,
                LastAttemptAt = DateTime.UtcNow,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };
            _dbContext.AccountLockouts.Add(lockout);
        }
        else
        {
            lockout.FailedAttempts++;
            lockout.LastAttemptAt = DateTime.UtcNow;
            lockout.UpdatedAt = DateTime.UtcNow;

            if (lockout.FailedAttempts >= MaxFailedAttempts)
            {
                lockout.LockedUntil = DateTime.UtcNow.Add(LockoutDuration);
                _logger.LogWarning("Account locked for user {UserId} until {LockedUntil}", userId, lockout.LockedUntil);

                // Publish UserAccountLockedEvent
                await _publishEndpoint.Publish(new UserAccountLockedEvent(
                    MessageId: Guid.NewGuid(),
                    MessageName: "UserAccountLockedEvent",
                    MessageType: MessageType.Event,
                    MessageVersion: "1.0.0",
                    PublishedBy: "AuthService",
                    ConsumedBy: ["NotificationService"],
                    CorrelationId: Guid.NewGuid(),
                    CausationId: null,
                    OccurredAtUtc: DateTimeOffset.UtcNow,
                    IsPublic: false,
                    Payload: new UserAccountLockedEventPayload(
                        UserId: userId.ToString(),
                        UserType: userType == UserType.Customer ? "Customer" : "Employee",
                        FailedAttemptCount: lockout.FailedAttempts,
                        LockedUntil: new DateTimeOffset(lockout.LockedUntil.Value),
                        LockedAt: DateTimeOffset.UtcNow
                    )
                ));
            }
        }

        await _dbContext.SaveChangesAsync();
    }
    /// <inheritdoc/>

    public async Task ResetFailedAttemptsAsync(Guid userId, UserType userType)
    {
        var lockout = await _dbContext.AccountLockouts
            .FirstOrDefaultAsync(l => l.UserId == userId && l.UserType == userType);

        if (lockout != null)
        {
            lockout.FailedAttempts = 0;
            lockout.LockedUntil = null;
            lockout.UpdatedAt = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();
        }
    }

    /// <inheritdoc/>
    public async Task<DateTime?> GetLockedUntilAsync(Guid userId, UserType userType)
    {
        var lockout = await _dbContext.AccountLockouts
            .FirstOrDefaultAsync(l => l.UserId == userId && l.UserType == userType);

        return lockout?.LockedUntil;
    }
}
