using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Data.Entities;
using Maliev.MessagingContracts.Generated;
using Maliev.MessagingContracts.Contracts.Auth;
using MassTransit;
using Microsoft.EntityFrameworkCore;

namespace Maliev.AuthService.Api.Services;
/// <summary>
/// Service for RefreshToken operations
/// </summary>

public class RefreshTokenService : IRefreshTokenService
{
    private readonly AuthDbContext _dbContext;
    private readonly ITokenGenerator _tokenGenerator;
    private readonly ILogger<RefreshTokenService> _logger;
    private readonly IPublishEndpoint _publishEndpoint;
    /// <summary>
    /// Initializes a new instance of the <see cref="RefreshTokenService"/> class.
    /// </summary>
    /// <param name="dbContext">The database context</param>
    /// <param name="tokenGenerator">The token generator</param>
    /// <param name="logger">The logger instance</param>
    /// <param name="publishEndpoint">The publish endpoint for events</param>

    public RefreshTokenService(
        AuthDbContext dbContext,
        ITokenGenerator tokenGenerator,
        ILogger<RefreshTokenService> logger,
        IPublishEndpoint publishEndpoint)
    {
        _dbContext = dbContext;
        _tokenGenerator = tokenGenerator;
        _logger = logger;
        _publishEndpoint = publishEndpoint;
    }

    /// <inheritdoc/>
    public async Task<(RefreshToken Entity, string TokenValue)> CreateRefreshTokenAsync(Guid userId, Guid principalId, UserType userType, string? email, string? name, string? ipAddress)
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
            PrincipalId = principalId,
            UserType = userType,
            TokenHash = tokenHash,
            Email = email,
            Name = name,
            IsUsed = false,
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            CreatedAt = DateTime.UtcNow,
            IpAddress = ipAddress
        };

        _dbContext.TokenFamilies.Add(tokenFamily);
        _dbContext.RefreshTokens.Add(refreshToken);
        await _dbContext.SaveChangesAsync();

        _logger.LogDebug("Created refresh token for user {UserId}, family {FamilyId}", userId, familyId);

        return (refreshToken, tokenValue);
    }

    /// <inheritdoc/>
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

            // Publish SuspiciousActivityDetectedEvent for token reuse
            await _publishEndpoint.Publish(new SuspiciousActivityDetectedEvent(
                MessageId: Guid.NewGuid(),
                MessageName: "SuspiciousActivityDetectedEvent",
                MessageType: MessageType.Event,
                MessageVersion: "1.0.0",
                PublishedBy: "AuthService",
                ConsumedBy: ["NotificationService"],
                CorrelationId: Guid.NewGuid(),
                CausationId: null,
                OccurredAtUtc: DateTimeOffset.UtcNow,
                IsPublic: false,
                Payload: new SuspiciousActivityDetectedEventPayload(
                    UserId: refreshToken.UserId.ToString(),
                    UserType: refreshToken.UserType == UserType.Customer ? "Customer" : "Employee",
                    ActivityType: "RefreshTokenReuse",
                    IpAddress: refreshToken.IpAddress,
                    TokenFamilyId: refreshToken.FamilyId.ToString(),
                    DetectedAt: DateTimeOffset.UtcNow
                )
            ));

            await RevokeTokenFamilyAsync(refreshToken.FamilyId, "Token reuse detected");
            return null;
        }

        return refreshToken;
    }

    /// <inheritdoc/>
    public async Task<(RefreshToken Entity, string TokenValue)> RotateRefreshTokenAsync(RefreshToken oldToken, string? ipAddress)
    {
        try
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
                PrincipalId = oldToken.PrincipalId,
                UserType = oldToken.UserType,
                TokenHash = tokenHash,
                Email = oldToken.Email,
                Name = oldToken.Name,
                IsUsed = false,
                ExpiresAt = DateTime.UtcNow.AddDays(7),
                CreatedAt = DateTime.UtcNow,
                IpAddress = ipAddress
            };

            oldToken.Family.LastRefreshAt = DateTime.UtcNow;

            _dbContext.RefreshTokens.Add(newToken);
            await _dbContext.SaveChangesAsync();

            _logger.LogDebug("Rotated refresh token for user {UserId}, family {FamilyId}",
                oldToken.UserId, oldToken.FamilyId);

            return (newToken, tokenValue);
        }
        catch (DbUpdateConcurrencyException)
        {
            _logger.LogWarning("Concurrency conflict detected during token rotation for family {FamilyId}. Token may have been reused.", oldToken.FamilyId);
            throw new InvalidOperationException("Token rotation failed due to concurrent update.");
        }
    }
    /// <inheritdoc/>
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

        // Determine revocation reason enum
        var revocationReason = reason.ToLowerInvariant() switch
        {
            "user logout" => "UserLogout",
            "token reuse detected" => "TokenReuse",
            _ => "Administrative"
        };

        // Publish RefreshTokenRevokedEvent
        await _publishEndpoint.Publish(new RefreshTokenRevokedEvent(
            MessageId: Guid.NewGuid(),
            MessageName: "RefreshTokenRevokedEvent",
            MessageType: MessageType.Event,
            MessageVersion: "1.0.0",
            PublishedBy: "AuthService",
            ConsumedBy: ["NotificationService"],
            CorrelationId: Guid.NewGuid(),
            CausationId: null,
            OccurredAtUtc: DateTimeOffset.UtcNow,
            IsPublic: false,
            Payload: new RefreshTokenRevokedEventPayload(
                UserId: family.UserId.ToString(),
                UserType: family.UserType == UserType.Customer ? "Customer" : "Employee",
                TokenFamilyId: familyId.ToString(),
                RevocationReason: revocationReason,
                RevokedAt: DateTimeOffset.UtcNow
            )
        ));
    }
    /// <inheritdoc/>
    public async Task<bool> IsTokenReuseDetectedAsync(string tokenHash)
    {
        var token = await _dbContext.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash);

        return token?.IsUsed == true;
    }
}
