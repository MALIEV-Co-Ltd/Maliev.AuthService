using Maliev.AuthService.Api.Services;
using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using Maliev.AuthService.Tests.Contract;

namespace Maliev.AuthService.Tests.Integration;

public class RateLimitServiceTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _fixture;

    public RateLimitServiceTests(TestWebApplicationFactory fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task RecordFailedAttemptAsync_NewIp_CreatesRecord()
    {
        // Arrange
        using var scope = _fixture.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var service = scope.ServiceProvider.GetRequiredService<IRateLimitService>();
        var ip = "1.2.3.4";

        // Act
        await service.RecordFailedAttemptAsync(ip);

        // Assert
        var record = await context.IpRateLimits.FirstOrDefaultAsync(r => r.IpAddress == ip);
        Assert.NotNull(record);
        Assert.Equal(1, record.FailedAttempts);
    }

    [Fact]
    public async Task IsRateLimitExceededAsync_ExpiredBlock_ResetsAttempts()
    {
        // Arrange
        using var scope = _fixture.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var service = scope.ServiceProvider.GetRequiredService<IRateLimitService>();
        var ip = "5.6.7.8";

        context.IpRateLimits.Add(new IpRateLimit
        {
            IpAddress = ip,
            FailedAttempts = 20,
            BlockedUntil = DateTime.UtcNow.AddMinutes(-1), // Expired
            WindowStart = DateTime.UtcNow.AddMinutes(-20),
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        });
        await context.SaveChangesAsync();

        // Act
        var isExceeded = await service.IsRateLimitExceededAsync(ip);

        // Assert
        Assert.False(isExceeded);
        var record = await context.IpRateLimits.AsNoTracking().FirstOrDefaultAsync(r => r.IpAddress == ip);
        Assert.Equal(0, record!.FailedAttempts);
        Assert.Null(record.BlockedUntil);
    }
}
