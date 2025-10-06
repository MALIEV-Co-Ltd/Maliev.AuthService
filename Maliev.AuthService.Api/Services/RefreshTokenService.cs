using Maliev.AuthService.Api.Options;
using Maliev.AuthService.Data.Entities;
using Maliev.AuthService.Data.Repositories;
using Microsoft.Extensions.Options;

namespace Maliev.AuthService.Api.Services;

/// <summary>
/// Service implementation for refresh token operations with RFC 9700 compliance.
/// </summary>
public class RefreshTokenService : IRefreshTokenService
{
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly ITokenFamilyRepository _tokenFamilyRepository;
    private readonly ITokenGenerator _tokenGenerator;
    private readonly JwtOptions _jwtOptions;
    private readonly ILogger<RefreshTokenService> _logger;

    public RefreshTokenService(
        IRefreshTokenRepository refreshTokenRepository,
        ITokenFamilyRepository tokenFamilyRepository,
        ITokenGenerator tokenGenerator,
        IOptions<JwtOptions> jwtOptions,
        ILogger<RefreshTokenService> logger)
    {
        _refreshTokenRepository = refreshTokenRepository;
        _tokenFamilyRepository = tokenFamilyRepository;
        _tokenGenerator = tokenGenerator;
        _jwtOptions = jwtOptions.Value;
        _logger = logger;
    }

    public async Task<Guid> CreateTokenFamilyAsync(string userId, UserType userType, CancellationToken cancellationToken = default)
    {
        var family = new TokenFamily
        {
            FamilyId = Guid.NewGuid(),
            UserId = userId,
            UserType = userType,
            CreatedAt = DateTime.UtcNow,
            LastUsedAt = DateTime.UtcNow,
            RefreshTokens = []
        };

        await _tokenFamilyRepository.CreateAsync(family, cancellationToken);
        return family.FamilyId;
    }

    public async Task<RefreshToken> StoreRefreshTokenAsync(
        string tokenHash,
        string userId,
        UserType userType,
        Guid familyId,
        DateTime expiresAt,
        CancellationToken cancellationToken = default)
    {
        var refreshToken = new RefreshToken
        {
            Id = Guid.NewGuid(),
            TokenHash = tokenHash,
            UserId = userId,
            UserType = userType,
            FamilyId = familyId,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = expiresAt,
            IsRevoked = false,
            IsUsed = false
        };

        return await _refreshTokenRepository.CreateAsync(refreshToken, cancellationToken);
    }

    public async Task<RefreshToken?> RotateRefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        var tokenHash = _tokenGenerator.HashRefreshToken(refreshToken);
        var storedToken = await _refreshTokenRepository.GetByTokenHashAsync(tokenHash, cancellationToken);

        if (storedToken == null)
        {
            _logger.LogWarning("Refresh token not found in database");
            return null;
        }

        // Check expiration
        if (storedToken.ExpiresAt < DateTime.UtcNow)
        {
            _logger.LogWarning("Refresh token expired: {TokenId}", storedToken.Id);
            return null;
        }

        // Check if revoked
        if (storedToken.IsRevoked)
        {
            _logger.LogWarning("Refresh token is revoked: {TokenId}", storedToken.Id);
            return null;
        }

        // **Reuse Detection (RFC 9700)**: If token is already used, invalidate entire family
        if (storedToken.IsUsed)
        {
            _logger.LogError("Refresh token reuse detected! Invalidating token family: {FamilyId}", storedToken.FamilyId);
            await _refreshTokenRepository.RevokeTokenFamilyAsync(storedToken.FamilyId, cancellationToken);
            return null; // Token family invalidated
        }

        // Mark current token as used with optimistic concurrency control
        var marked = await _refreshTokenRepository.MarkAsUsedAsync(storedToken.Id, storedToken.Version, cancellationToken);
        if (!marked)
        {
            // Concurrent modification detected - another request used this token simultaneously
            _logger.LogError("Concurrent token use detected! Invalidating token family: {FamilyId}", storedToken.FamilyId);
            await _refreshTokenRepository.RevokeTokenFamilyAsync(storedToken.FamilyId, cancellationToken);
            return null;
        }

        // Generate new refresh token (rotation)
        var newRefreshToken = _tokenGenerator.GenerateRefreshToken();
        var newTokenHash = _tokenGenerator.HashRefreshToken(newRefreshToken);
        var expiresAt = DateTime.UtcNow.AddSeconds(_jwtOptions.RefreshTokenLifetimeSeconds);

        var newToken = await StoreRefreshTokenAsync(
            newTokenHash,
            storedToken.UserId,
            storedToken.UserType,
            storedToken.FamilyId,
            expiresAt,
            cancellationToken);

        // Update family last used timestamp
        await _tokenFamilyRepository.UpdateLastUsedAsync(storedToken.FamilyId, cancellationToken);

        // Attach plaintext token for response (not stored in DB)
        newToken.TokenHash = newRefreshToken; // Temporarily store plaintext for response

        return newToken;
    }

    public async Task<RefreshToken?> ValidateRefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        var tokenHash = _tokenGenerator.HashRefreshToken(refreshToken);
        var storedToken = await _refreshTokenRepository.GetByTokenHashAsync(tokenHash, cancellationToken);

        if (storedToken == null || storedToken.ExpiresAt < DateTime.UtcNow || storedToken.IsRevoked || storedToken.IsUsed)
        {
            return null;
        }

        return storedToken;
    }
}
