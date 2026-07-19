using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Domain.Entities;
using Maliev.AuthService.Infrastructure.DbContexts;
using Maliev.AuthService.Tests.Contract;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Maliev.AuthService.Tests.Integration;

public class RefreshTokenServiceIntegrationTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _fixture;

    public RefreshTokenServiceIntegrationTests(TestWebApplicationFactory fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task CreateRefreshTokenAsync_CreatesTokenAndFamily()
    {
        await _fixture.CleanDatabaseAsync();

        using var scope = _fixture.Services.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<IRefreshTokenService>();

        var userId = Guid.NewGuid();
        var principalId = Guid.NewGuid();

        var (entity, tokenValue) = await service.CreateRefreshTokenAsync(
            userId, principalId, UserType.Customer, "test@test.com", "Test", "127.0.0.1");

        Assert.NotNull(entity);
        Assert.NotEmpty(tokenValue);
        Assert.Equal(userId, entity.UserId);
    }

    [Fact]
    public async Task ValidateRefreshTokenAsync_ValidToken_ReturnsUserInfo()
    {
        await _fixture.CleanDatabaseAsync();

        using var scope = _fixture.Services.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<IRefreshTokenService>();

        var userId = Guid.NewGuid();
        var principalId = Guid.NewGuid();

        var (_, tokenValue) = await service.CreateRefreshTokenAsync(
            userId, principalId, UserType.Employee, "employee@test.com", "Employee Name", "192.168.1.1");

        var result = await service.ValidateRefreshTokenAsync(tokenValue);

        Assert.NotNull(result);
        Assert.Equal(userId, result.UserId);
        Assert.Equal(principalId, result.PrincipalId);
        Assert.Equal(UserType.Employee, result.UserType);
        Assert.Equal("employee@test.com", result.Email);
    }

    [Fact]
    public async Task RevokeTokenFamilyAsync_WithReason_RecordsInDatabase()
    {
        await _fixture.CleanDatabaseAsync();

        using var scope = _fixture.Services.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<IRefreshTokenService>();

        var userId = Guid.NewGuid();
        var principalId = Guid.NewGuid();

        var (token, _) = await service.CreateRefreshTokenAsync(
            userId, principalId, UserType.Customer, "user@test.com", "User", null);

        await service.RevokeTokenFamilyAsync(token.FamilyId, "Security concern");

        using var verifyScope = _fixture.Services.CreateScope();
        var context = verifyScope.ServiceProvider.GetRequiredService<AuthDbContext>();

        var revokedToken = await context.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.FamilyId == token.FamilyId);

        Assert.NotNull(revokedToken);
        Assert.True(revokedToken.IsUsed);
    }
}
