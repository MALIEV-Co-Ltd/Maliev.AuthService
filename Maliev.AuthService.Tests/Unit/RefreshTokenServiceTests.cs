using Maliev.AuthService.Api.Services;
using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Data.Entities;
using Maliev.AuthService.Tests.Infrastructure;
using Maliev.MessagingContracts;
using Maliev.MessagingContracts.Contracts.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using MassTransit;

namespace Maliev.AuthService.Tests.Unit;

public class RefreshTokenServiceTests : IClassFixture<TestDatabaseFixture>, IAsyncLifetime
{
    private readonly TestDatabaseFixture _fixture;
    private readonly Mock<ITokenGenerator> _tokenGeneratorMock;
    private readonly Mock<ILogger<RefreshTokenService>> _loggerMock;
    private readonly Mock<IPublishEndpoint> _publishEndpointMock;
    private RefreshTokenService? _service;

    public RefreshTokenServiceTests(TestDatabaseFixture fixture)
    {
        _fixture = fixture;
        _tokenGeneratorMock = new Mock<ITokenGenerator>();
        _loggerMock = new Mock<ILogger<RefreshTokenService>>();
        _publishEndpointMock = new Mock<IPublishEndpoint>();
    }

    public async Task InitializeAsync()
    {
        await _fixture.InitializeAsync();
        _service = new RefreshTokenService(
            _fixture.CreateDbContext(),
            _tokenGeneratorMock.Object,
            _loggerMock.Object,
            _publishEndpointMock.Object);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task CreateRefreshTokenAsync_CreatesTokenAndFamily()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var principalId = Guid.NewGuid();
        _tokenGeneratorMock.Setup(g => g.GenerateRefreshToken()).Returns("token-value");
        _tokenGeneratorMock.Setup(g => g.HashToken("token-value")).Returns("token-hash");

        // Act
        var (entity, tokenValue) = await _service!.CreateRefreshTokenAsync(userId, principalId, UserType.Customer, "user@test.com", "User", "127.0.0.1");

        // Assert
        Assert.Equal("token-value", tokenValue);
        Assert.Equal("token-hash", entity.TokenHash);
        Assert.Equal(userId, entity.UserId);
        Assert.Equal(principalId, entity.PrincipalId);
        Assert.False(entity.IsUsed);

        using var dbContext = _fixture.CreateDbContext();
        var family = await dbContext.TokenFamilies.FindAsync(entity.FamilyId);
        Assert.NotNull(family);
        Assert.Equal(userId, family.UserId);
    }

    [Fact]
    public async Task ValidateRefreshTokenAsync_ValidToken_ReturnsToken()
    {
        // Arrange
        var userId = Guid.NewGuid();
        _tokenGeneratorMock.Setup(g => g.HashToken("valid-token")).Returns("valid-hash");

        using (var dbContext = _fixture.CreateDbContext())
        {
            var familyId = Guid.NewGuid();
            dbContext.TokenFamilies.Add(new TokenFamily { FamilyId = familyId, UserId = userId, UserType = UserType.Customer });
            dbContext.RefreshTokens.Add(new RefreshToken
            {
                Id = Guid.NewGuid(),
                FamilyId = familyId,
                UserId = userId,
                TokenHash = "valid-hash",
                ExpiresAt = DateTime.UtcNow.AddDays(1),
                IsUsed = false
            });
            await dbContext.SaveChangesAsync();
        }

        // Act
        var result = await _service!.ValidateRefreshTokenAsync("valid-token");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("valid-hash", result.TokenHash);
    }

    [Fact]
    public async Task ValidateRefreshTokenAsync_TokenReuse_RevokesFamilyAndReturnsNull()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var familyId = Guid.NewGuid();
        _tokenGeneratorMock.Setup(g => g.HashToken("reused-token")).Returns("reused-hash");

        using (var dbContext = _fixture.CreateDbContext())
        {
            dbContext.TokenFamilies.Add(new TokenFamily { FamilyId = familyId, UserId = userId, UserType = UserType.Customer });
            dbContext.RefreshTokens.Add(new RefreshToken
            {
                Id = Guid.NewGuid(),
                FamilyId = familyId,
                UserId = userId,
                TokenHash = "reused-hash",
                ExpiresAt = DateTime.UtcNow.AddDays(1),
                IsUsed = true
            });
            dbContext.RefreshTokens.Add(new RefreshToken
            {
                Id = Guid.NewGuid(),
                FamilyId = familyId,
                UserId = userId,
                TokenHash = "other-token",
                ExpiresAt = DateTime.UtcNow.AddDays(1),
                IsUsed = false
            });
            await dbContext.SaveChangesAsync();
        }

        // Act
        var result = await _service!.ValidateRefreshTokenAsync("reused-token");

        // Assert
        Assert.Null(result);

        using (var dbContext = _fixture.CreateDbContext())
        {
            var otherToken = await dbContext.RefreshTokens.FirstOrDefaultAsync(rt => rt.TokenHash == "other-token");
            Assert.True(otherToken!.IsUsed); // Should be revoked
        }
        _publishEndpointMock.Verify(p => p.Publish(It.IsAny<SuspiciousActivityDetectedEvent>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task IsTokenReuseDetectedAsync_UsedToken_ReturnsTrue()
    {
        // Arrange
        var tokenHash = "used-hash";
        var userId = Guid.NewGuid();
        var familyId = Guid.NewGuid();
        using (var dbContext = _fixture.CreateDbContext())
        {
            dbContext.TokenFamilies.Add(new TokenFamily { FamilyId = familyId, UserId = userId, UserType = UserType.Customer });
            dbContext.RefreshTokens.Add(new RefreshToken
            {
                Id = Guid.NewGuid(),
                FamilyId = familyId,
                UserId = userId,
                TokenHash = tokenHash,
                IsUsed = true
            });
            await dbContext.SaveChangesAsync();
        }

        // Act
        var result = await _service!.IsTokenReuseDetectedAsync(tokenHash);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task IsTokenReuseDetectedAsync_UnusedToken_ReturnsFalse()
    {
        // Arrange
        var tokenHash = "unused-hash";
        var userId = Guid.NewGuid();
        var familyId = Guid.NewGuid();
        using (var dbContext = _fixture.CreateDbContext())
        {
            dbContext.TokenFamilies.Add(new TokenFamily { FamilyId = familyId, UserId = userId, UserType = UserType.Customer });
            dbContext.RefreshTokens.Add(new RefreshToken
            {
                Id = Guid.NewGuid(),
                FamilyId = familyId,
                UserId = userId,
                TokenHash = tokenHash,
                IsUsed = false
            });
            await dbContext.SaveChangesAsync();
        }

        // Act
        var result = await _service!.IsTokenReuseDetectedAsync(tokenHash);

        // Assert
        Assert.False(result);
    }
}
