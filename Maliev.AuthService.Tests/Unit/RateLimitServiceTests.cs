using Maliev.AuthService.Api.Services;
using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Data.Entities;
using Maliev.AuthService.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public class RateLimitServiceTests : IClassFixture<TestDatabaseFixture>, IAsyncLifetime
{
    private readonly TestDatabaseFixture _fixture;
    private readonly Mock<ILogger<RateLimitService>> _loggerMock;
    private RateLimitService? _service;

    public RateLimitServiceTests(TestDatabaseFixture fixture)
    {
        _fixture = fixture;
        _loggerMock = new Mock<ILogger<RateLimitService>>();
    }

    public async Task InitializeAsync()
    {
        await _fixture.InitializeAsync();
        _service = new RateLimitService(
            _fixture.CreateDbContext(),
            _loggerMock.Object);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task IsRateLimitExceededAsync_NotExceeded_ReturnsFalse()
    {
        // Arrange
        var ipAddress = "1.1.1.1";

        // Act
        var result = await _service!.IsRateLimitExceededAsync(ipAddress);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task IsRateLimitExceededAsync_Exceeded_ReturnsTrue()
    {
        // Arrange
        var ipAddress = "2.2.2.2";
        using (var dbContext = _fixture.CreateDbContext())
        {
            dbContext.IpRateLimits.Add(new IpRateLimit
            {
                Id = Guid.NewGuid(),
                IpAddress = ipAddress,
                FailedAttempts = 20,
                BlockedUntil = DateTime.UtcNow.AddMinutes(15)
            });
            await dbContext.SaveChangesAsync();
        }

        // Act
        var result = await _service!.IsRateLimitExceededAsync(ipAddress);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task RecordFailedAttemptAsync_IncrementsCount()
    {
        // Arrange
        var ipAddress = "3.3.3.3";

        // Act
        await _service!.RecordFailedAttemptAsync(ipAddress);
        await _service!.RecordFailedAttemptAsync(ipAddress);

        // Assert
        using var dbContext = _fixture.CreateDbContext();
        var limit = await dbContext.IpRateLimits.FirstAsync(l => l.IpAddress == ipAddress);
        Assert.Equal(2, limit.FailedAttempts);
    }

    [Fact]
    public async Task RecordFailedAttemptAsync_MaxAttempts_BlocksIp()
    {
        // Arrange
        var ipAddress = "4.4.4.4";

        // Act
        for (int i = 0; i < 20; i++)
        {
            await _service!.RecordFailedAttemptAsync(ipAddress);
        }

        // Assert
        using var dbContext = _fixture.CreateDbContext();
        var limit = await dbContext.IpRateLimits.FirstAsync(l => l.IpAddress == ipAddress);
        Assert.Equal(20, limit.FailedAttempts);
        Assert.NotNull(limit.BlockedUntil);
    }
}
