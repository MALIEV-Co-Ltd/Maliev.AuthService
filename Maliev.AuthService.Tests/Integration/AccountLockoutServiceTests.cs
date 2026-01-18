using Maliev.AuthService.Api.Services;
using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using Maliev.AuthService.Tests.Contract;
using Maliev.MessagingContracts.Generated;

namespace Maliev.AuthService.Api.Tests.Integration;

public class AccountLockoutServiceTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _fixture;

    public AccountLockoutServiceTests(TestWebApplicationFactory fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task RecordFailedAttemptAsync_MaxAttempts_LocksAccountAndPublishesEvent()
    {
        // Arrange
        using var scope = _fixture.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var service = scope.ServiceProvider.GetRequiredService<IAccountLockoutService>();
        var userId = Guid.NewGuid();

        // Act - Record 5 failed attempts (Max is 5)
        for (int i = 0; i < 5; i++)
        {
            await service.RecordFailedAttemptAsync(userId, UserType.Customer);
        }

        // Assert
        var record = await context.AccountLockouts.AsNoTracking().FirstOrDefaultAsync(l => l.UserId == userId);
        Assert.NotNull(record);
        Assert.Equal(5, record.FailedAttempts);
        Assert.NotNull(record.LockedUntil);
        Assert.True(record.LockedUntil > DateTime.UtcNow);

        var isLocked = await service.IsAccountLockedAsync(userId, UserType.Customer);
        Assert.True(isLocked);
    }

    [Fact]
    public async Task IsAccountLockedAsync_ExpiredLockout_ResetsAttempts()
    {
        // Arrange
        using var scope = _fixture.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var service = scope.ServiceProvider.GetRequiredService<IAccountLockoutService>();
        var userId = Guid.NewGuid();

        context.AccountLockouts.Add(new AccountLockout
        {
            UserId = userId,
            UserType = UserType.Customer,
            FailedAttempts = 5,
            LockedUntil = DateTime.UtcNow.AddMinutes(-1), // Expired
            LastAttemptAt = DateTime.UtcNow.AddMinutes(-20),
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        });
        await context.SaveChangesAsync();

        // Act
        var isLocked = await service.IsAccountLockedAsync(userId, UserType.Customer);

        // Assert
        Assert.False(isLocked);
        var record = await context.AccountLockouts.AsNoTracking().FirstOrDefaultAsync(l => l.UserId == userId);
        Assert.Equal(0, record!.FailedAttempts);
        Assert.Null(record.LockedUntil);
    }
}
