using Maliev.AuthService.Api.Services;
using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Data.Entities;
using Maliev.AuthService.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using MassTransit;

namespace Maliev.AuthService.Tests.Unit;

public class AccountLockoutServiceTests : IClassFixture<TestDatabaseFixture>, IAsyncLifetime
{
    private readonly TestDatabaseFixture _fixture;
    private readonly Mock<ILogger<AccountLockoutService>> _loggerMock;
    private readonly Mock<IPublishEndpoint> _publishEndpointMock;
    private AccountLockoutService? _service;

    public AccountLockoutServiceTests(TestDatabaseFixture fixture)
    {
        _fixture = fixture;
        _loggerMock = new Mock<ILogger<AccountLockoutService>>();
        _publishEndpointMock = new Mock<IPublishEndpoint>();
    }

    public async Task InitializeAsync()
    {
        await _fixture.InitializeAsync();
        _service = new AccountLockoutService(
            _fixture.CreateDbContext(),
            _loggerMock.Object,
            _publishEndpointMock.Object);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task IsAccountLockedAsync_NotLocked_ReturnsFalse()
    {
        // Arrange
        var userId = Guid.NewGuid();

        // Act
        var result = await _service!.IsAccountLockedAsync(userId, UserType.Customer);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task IsAccountLockedAsync_Locked_ReturnsTrue()
    {
        // Arrange
        var userId = Guid.NewGuid();
        using (var dbContext = _fixture.CreateDbContext())
        {
            dbContext.AccountLockouts.Add(new AccountLockout
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                UserType = UserType.Customer,
                FailedAttempts = 5,
                LockedUntil = DateTime.UtcNow.AddMinutes(15)
            });
            await dbContext.SaveChangesAsync();
        }

        // Act
        var result = await _service!.IsAccountLockedAsync(userId, UserType.Customer);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task RecordFailedAttemptAsync_IncrementsCount()
    {
        // Arrange
        var userId = Guid.NewGuid();

        // Act
        await _service!.RecordFailedAttemptAsync(userId, UserType.Customer);
        await _service!.RecordFailedAttemptAsync(userId, UserType.Customer);

        // Assert
        using var dbContext = _fixture.CreateDbContext();
        var lockout = await dbContext.AccountLockouts.FirstAsync(l => l.UserId == userId);
        Assert.Equal(2, lockout.FailedAttempts);
    }

    [Fact]
    public async Task RecordFailedAttemptAsync_MaxAttempts_LocksAccount()
    {
        // Arrange
        var userId = Guid.NewGuid();

        // Act
        for (int i = 0; i < 5; i++)
        {
            await _service!.RecordFailedAttemptAsync(userId, UserType.Customer);
        }

        // Assert
        using var dbContext = _fixture.CreateDbContext();
        var lockout = await dbContext.AccountLockouts.FirstAsync(l => l.UserId == userId);
        Assert.Equal(5, lockout.FailedAttempts);
        Assert.NotNull(lockout.LockedUntil);
        _publishEndpointMock.Verify(p => p.Publish(It.IsAny<Maliev.MessagingContracts.Generated.UserAccountLockedEvent>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ResetFailedAttemptsAsync_ResetsCount()
    {
        // Arrange
        var userId = Guid.NewGuid();
        using (var dbContext = _fixture.CreateDbContext())
        {
            dbContext.AccountLockouts.Add(new AccountLockout
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                UserType = UserType.Customer,
                FailedAttempts = 3,
                LockedUntil = DateTime.UtcNow.AddMinutes(15)
            });
            await dbContext.SaveChangesAsync();
        }

        // Act
        await _service!.ResetFailedAttemptsAsync(userId, UserType.Customer);

        // Assert
        using (var dbContext = _fixture.CreateDbContext())
        {
            var lockout = await dbContext.AccountLockouts.FirstAsync(l => l.UserId == userId);
            Assert.Equal(0, lockout.FailedAttempts);
            Assert.Null(lockout.LockedUntil);
        }
    }
}
