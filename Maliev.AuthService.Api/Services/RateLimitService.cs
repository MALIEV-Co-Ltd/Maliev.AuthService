using Microsoft.EntityFrameworkCore;
using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Data.Entities;

namespace Maliev.AuthService.Api.Services;

/// <summary>
/// Service for RateLimit operations
/// </summary>
public class RateLimitService : IRateLimitService
{
    private readonly AuthDbContext _dbContext;
    private readonly ILogger<RateLimitService> _logger;
    private const int MaxFailedAttempts = 20;
    private static readonly TimeSpan WindowDuration = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan BlockDuration = TimeSpan.FromMinutes(15);
    /// <summary>
    /// Initializes a new instance of the <see cref="RateLimitService"/> class.
    /// </summary>
    /// <param name="dbContext">The database context</param>
    /// <param name="logger">The logger instance</param>

    public RateLimitService(AuthDbContext dbContext, ILogger<RateLimitService> logger)
    {
        _dbContext = dbContext;
        _logger = logger;
    }
    /// <inheritdoc/>
    public async Task<bool> IsRateLimitExceededAsync(string ipAddress)
    {
        var rateLimit = await _dbContext.IpRateLimits
            .FirstOrDefaultAsync(r => r.IpAddress == ipAddress);

        if (rateLimit == null)
        {
            _logger.LogInformation("No rate limit record found for IP: {IpAddress}", ipAddress);
            return false;
        }

        _logger.LogInformation("Rate limit check for IP: {IpAddress}. FailedAttempts: {FailedAttempts}, BlockedUntil: {BlockedUntil}",
            ipAddress, rateLimit.FailedAttempts, rateLimit.BlockedUntil);

        // Check if currently blocked
        if (rateLimit.BlockedUntil.HasValue && rateLimit.BlockedUntil.Value > DateTime.UtcNow)
        {
            return true;
        }

        // Block expired, reset
        if (rateLimit.BlockedUntil.HasValue && rateLimit.BlockedUntil.Value <= DateTime.UtcNow)
        {
            rateLimit.FailedAttempts = 0;
            rateLimit.BlockedUntil = null;
            rateLimit.WindowStart = DateTime.UtcNow;
            rateLimit.UpdatedAt = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();
            return false;
        }

        // Check if window expired
        if (DateTime.UtcNow - rateLimit.WindowStart > WindowDuration)
        {
            rateLimit.FailedAttempts = 0;
            rateLimit.WindowStart = DateTime.UtcNow;
            rateLimit.UpdatedAt = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();
            return false;
        }

        // Check if rate limit exceeded in current window
        return rateLimit.FailedAttempts >= MaxFailedAttempts;
    }
    /// <inheritdoc/>
    public async Task RecordFailedAttemptAsync(string ipAddress)
    {
        try
        {
            await RecordFailedAttemptInternalAsync(ipAddress);
        }
        catch (DbUpdateException)
        {
            // Handle concurrency/duplicate key race condition
            // Detach only matching IpRateLimit entities to avoid losing other pending changes
            var entries = _dbContext.ChangeTracker.Entries<IpRateLimit>()
                .Where(e => e.Entity.IpAddress == ipAddress)
                .ToList();

            foreach (var entry in entries)
            {
                entry.State = EntityState.Detached;
            }
            await RecordFailedAttemptInternalAsync(ipAddress);
        }
    }

    private async Task RecordFailedAttemptInternalAsync(string ipAddress)
    {
        var rateLimit = await _dbContext.IpRateLimits
            .FirstOrDefaultAsync(r => r.IpAddress == ipAddress);

        if (rateLimit == null)
        {
            rateLimit = new IpRateLimit
            {
                Id = Guid.NewGuid(),
                IpAddress = ipAddress,
                FailedAttempts = 1,
                WindowStart = DateTime.UtcNow,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };
            _dbContext.IpRateLimits.Add(rateLimit);
        }
        else
        {
            // Check if window expired
            if (DateTime.UtcNow - rateLimit.WindowStart > WindowDuration)
            {
                rateLimit.FailedAttempts = 1;
                rateLimit.WindowStart = DateTime.UtcNow;
            }
            else
            {
                rateLimit.FailedAttempts++;
            }

            rateLimit.UpdatedAt = DateTime.UtcNow;

            if (rateLimit.FailedAttempts >= MaxFailedAttempts)
            {
                rateLimit.BlockedUntil = DateTime.UtcNow.Add(BlockDuration);
                _logger.LogWarning("IP {IpAddress} blocked until {BlockedUntil}", ipAddress, rateLimit.BlockedUntil);
            }
        }

        await _dbContext.SaveChangesAsync();
    }

    /// <inheritdoc/>
    public async Task<DateTime?> GetBlockedUntilAsync(string ipAddress)
    {
        var rateLimit = await _dbContext.IpRateLimits
            .FirstOrDefaultAsync(r => r.IpAddress == ipAddress);

        return rateLimit?.BlockedUntil;
    }
}
