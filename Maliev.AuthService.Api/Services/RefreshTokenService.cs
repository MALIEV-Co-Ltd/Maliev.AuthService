using Microsoft.EntityFrameworkCore;
using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Data.Entities;

namespace Maliev.AuthService.Api.Services;

public class RefreshTokenService : IRefreshTokenService
{
    private readonly AuthDbContext _dbContext;
    private readonly ITokenGenerator _tokenGenerator;
    private readonly ILogger<RefreshTokenService> _logger;

    public RefreshTokenService(
        AuthDbContext dbContext,
        ITokenGenerator tokenGenerator,
        ILogger<RefreshTokenService> logger)
    {
        _dbContext = dbContext;
        _tokenGenerator = tokenGenerator;
        _logger = logger;
    }

    public async Task<(RefreshToken Entity, string TokenValue)> CreateRefreshTokenAsync(Guid userId, UserType userType, string? ipAddress)
    {
        var familyId = Guid.NewGuid();
        var tokenValue = _tokenGenerator.GenerateRefreshToken();
        var tokenHash = _tokenGenerator.HashToken(tokenValue);

        var tokenFamily = new TokenFamily
        {
            FamilyId = familyId,
            UserId = userId,
            UserType = userType,
            CreatedAt = DateTime.UtcNow,
            LastRefreshAt = DateTime.UtcNow
        };

        var refreshToken = new RefreshToken
        {
            Id = Guid.NewGuid(),
            FamilyId = familyId,
            UserId = userId,
            UserType = userType,
            TokenHash = tokenHash,
            IsUsed = false,
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            CreatedAt = DateTime.UtcNow,
            IpAddress = ipAddress
        };

        _dbContext.TokenFamilies.Add(tokenFamily);
        _dbContext.RefreshTokens.Add(refreshToken);
        await _dbContext.SaveChangesAsync();

        _logger.LogInformation("Created refresh token for user {UserId}, family {FamilyId}", userId, familyId);

        return (refreshToken, tokenValue);
    }

    public async Task<RefreshToken?> ValidateRefreshTokenAsync(string token)
    {
        var tokenHash = _tokenGenerator.HashToken(token);

        var refreshToken = await _dbContext.RefreshTokens
            .Include(rt => rt.Family)
            .FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash);

        if (refreshToken == null)
        {
            _logger.LogWarning("Refresh token not found");
            return null;
        }

        if (refreshToken.ExpiresAt < DateTime.UtcNow)
        {
            _logger.LogWarning("Refresh token expired for user {UserId}", refreshToken.UserId);
            return null;
        }

        if (refreshToken.IsUsed)
        {
            _logger.LogWarning("Token reuse detected for user {UserId}, family {FamilyId}",
                refreshToken.UserId, refreshToken.FamilyId);
            await RevokeTokenFamilyAsync(refreshToken.FamilyId, "Token reuse detected");
            return null;
        }

        return refreshToken;
    }

    public async Task<(RefreshToken Entity, string TokenValue)> RotateRefreshTokenAsync(RefreshToken oldToken, string? ipAddress)
    {
        oldToken.IsUsed = true;
        oldToken.UsedAt = DateTime.UtcNow;

        var tokenValue = _tokenGenerator.GenerateRefreshToken();
        var tokenHash = _tokenGenerator.HashToken(tokenValue);

        var newToken = new RefreshToken
        {
            Id = Guid.NewGuid(),
            FamilyId = oldToken.FamilyId,
            UserId = oldToken.UserId,
            UserType = oldToken.UserType,
            TokenHash = tokenHash,
            IsUsed = false,
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            CreatedAt = DateTime.UtcNow,
            IpAddress = ipAddress
        };

        oldToken.Family.LastRefreshAt = DateTime.UtcNow;

        _dbContext.RefreshTokens.Add(newToken);
        await _dbContext.SaveChangesAsync();

        _logger.LogInformation("Rotated refresh token for user {UserId}, family {FamilyId}",
            oldToken.UserId, oldToken.FamilyId);

        return (newToken, tokenValue);
    }

    public async Task RevokeTokenFamilyAsync(Guid familyId, string reason)
    {
        var family = await _dbContext.TokenFamilies
            .Include(f => f.RefreshTokens)
            .FirstOrDefaultAsync(f => f.FamilyId == familyId);

        if (family == null)
        {
            _logger.LogWarning("Token family {FamilyId} not found for revocation", familyId);
            return;
        }

        foreach (var token in family.RefreshTokens.Where(t => !t.IsUsed))
        {
            token.IsUsed = true;
            token.UsedAt = DateTime.UtcNow;
        }

        await _dbContext.SaveChangesAsync();

        _logger.LogWarning("Revoked token family {FamilyId} for user {UserId}. Reason: {Reason}",
            familyId, family.UserId, reason);
    }

    public async Task<bool> IsTokenReuseDetectedAsync(string tokenHash)
    {
        var token = await _dbContext.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash);

        return token?.IsUsed == true;
    }
}
