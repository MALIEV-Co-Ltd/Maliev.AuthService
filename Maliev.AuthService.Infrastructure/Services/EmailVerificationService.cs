using System.Security.Cryptography;
using Maliev.AuthService.Application.DTOs.Response;
using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Domain.Entities;
using Maliev.AuthService.Infrastructure.DbContexts;
using Maliev.MessagingContracts;
using Maliev.MessagingContracts.Contracts.Auth;
using MassTransit;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Maliev.AuthService.Infrastructure.Services;

/// <summary>
/// Manages email verification lifecycle including initiation, verification, and resending.
/// </summary>
public class EmailVerificationService : IEmailVerificationService
{
    private readonly AuthDbContext _dbContext;
    private readonly IPublishEndpoint _publishEndpoint;
    private readonly ILogger<EmailVerificationService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="EmailVerificationService"/> class.
    /// </summary>
    /// <param name="dbContext">The database context.</param>
    /// <param name="publishEndpoint">The publish endpoint for events.</param>
    /// <param name="logger">The logger instance.</param>
    public EmailVerificationService(
        AuthDbContext dbContext,
        IPublishEndpoint publishEndpoint,
        ILogger<EmailVerificationService> logger)
    {
        _dbContext = dbContext;
        _publishEndpoint = publishEndpoint;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<InitiateVerificationResult> InitiateVerificationAsync(Guid principalId, string email, string firstName, CancellationToken ct)
    {
        var principal = await _dbContext.UserPrincipals
            .FirstOrDefaultAsync(p => p.Id == principalId, ct);

        if (principal == null)
        {
            _logger.LogWarning("Initiate verification failed: principal {PrincipalId} not found", principalId);
            return new InitiateVerificationResult(false, "principal_not_found", "User principal not found", null);
        }

        if (principal.EmailVerifiedAtUtc.HasValue)
        {
            _logger.LogWarning("Initiate verification failed: email already verified for principal {PrincipalId}", principalId);
            return new InitiateVerificationResult(false, "already_verified", "Email is already verified", null);
        }

        // Check cooldown: allow resend only after 60 seconds
        var recentToken = await _dbContext.VerificationTokens
            .Where(t => t.PrincipalId == principalId && !t.IsUsed && t.ExpiresAt > DateTime.UtcNow)
            .OrderByDescending(t => t.CreatedAt)
            .FirstOrDefaultAsync(ct);

        if (recentToken != null)
        {
            var timeSinceLastToken = DateTime.UtcNow - recentToken.CreatedAt;
            if (timeSinceLastToken.TotalSeconds < 60)
            {
                var cooldownUntil = recentToken.CreatedAt.AddSeconds(60);
                _logger.LogWarning("Initiate verification failed: cooldown active for principal {PrincipalId}, retry after {Cooldown}", principalId, cooldownUntil);
                return new InitiateVerificationResult(false, "cooldown_active", "Please wait before requesting a new verification email", cooldownUntil);
            }
        }

        // Generate random token
        var tokenBytes = RandomNumberGenerator.GetBytes(32);
        var tokenValue = Convert.ToHexString(tokenBytes).ToLowerInvariant();
        var tokenHash = Convert.ToHexString(SHA256.HashData(tokenBytes)).ToLowerInvariant();

        var verificationToken = new VerificationToken
        {
            Id = Guid.NewGuid(),
            PrincipalId = principalId,
            TokenHash = tokenHash,
            Email = email,
            ExpiresAt = DateTime.UtcNow.AddHours(24),
            IsUsed = false,
            CreatedAt = DateTime.UtcNow
        };

        _dbContext.VerificationTokens.Add(verificationToken);
        await _dbContext.SaveChangesAsync(ct);

        _logger.LogInformation("Created verification token for principal {PrincipalId}, email {Email}", principalId, email);

        // Publish event to trigger email sending
        await _publishEndpoint.Publish(new VerificationEmailRequestedEvent(
            MessageId: Guid.NewGuid(),
            MessageName: "VerificationEmailRequestedEvent",
            MessageType: MessageType.Event,
            MessageVersion: "1.0.0",
            PublishedBy: "AuthService",
            ConsumedBy: new[] { "NotificationService" },
            CorrelationId: Guid.NewGuid(),
            CausationId: null,
            OccurredAtUtc: DateTimeOffset.UtcNow,
            IsPublic: false,
            Payload: new VerificationEmailRequestedEventPayload(
                PrincipalId: principalId,
                Email: email,
                FirstName: firstName,
                VerificationToken: tokenValue,
                ExpiresAt: DateTimeOffset.UtcNow.AddHours(24)
            )
        ), ct);

        return new InitiateVerificationResult(true, null, null, null);
    }

    /// <inheritdoc/>
    public async Task<VerifyEmailResult> VerifyEmailAsync(string token, CancellationToken ct)
    {
        var tokenHash = Convert.ToHexString(SHA256.HashData(Convert.FromHexString(token))).ToLowerInvariant();

        var verificationToken = await _dbContext.VerificationTokens
            .FirstOrDefaultAsync(t => t.TokenHash == tokenHash, ct);

        if (verificationToken == null)
        {
            _logger.LogWarning("Verify email failed: token not found");
            return new VerifyEmailResult(false, "invalid_token", "Verification token not found");
        }

        if (verificationToken.IsUsed)
        {
            _logger.LogWarning("Verify email failed: token already used for principal {PrincipalId}", verificationToken.PrincipalId);
            return new VerifyEmailResult(false, "token_used", "Verification token has already been used");
        }

        if (verificationToken.ExpiresAt < DateTime.UtcNow)
        {
            _logger.LogWarning("Verify email failed: token expired for principal {PrincipalId}", verificationToken.PrincipalId);
            return new VerifyEmailResult(false, "token_expired", "Verification token has expired");
        }

        // Mark token as used
        verificationToken.IsUsed = true;
        verificationToken.UsedAt = DateTime.UtcNow;

        // Update principal
        var principal = await _dbContext.UserPrincipals
            .FirstOrDefaultAsync(p => p.Id == verificationToken.PrincipalId, ct);

        if (principal != null)
        {
            principal.EmailVerifiedAtUtc = DateTime.UtcNow;
            principal.UpdatedAt = DateTime.UtcNow;
        }

        await _dbContext.SaveChangesAsync(ct);

        _logger.LogInformation("Email verified for principal {PrincipalId}", verificationToken.PrincipalId);

        // Publish event
        await _publishEndpoint.Publish(new EmailVerifiedEvent(
            MessageId: Guid.NewGuid(),
            MessageName: "EmailVerifiedEvent",
            MessageType: MessageType.Event,
            MessageVersion: "1.0.0",
            PublishedBy: "AuthService",
            ConsumedBy: new[] { "NotificationService", "CustomerService" },
            CorrelationId: Guid.NewGuid(),
            CausationId: null,
            OccurredAtUtc: DateTimeOffset.UtcNow,
            IsPublic: false,
            Payload: new EmailVerifiedEventPayload(
                PrincipalId: verificationToken.PrincipalId,
                Email: verificationToken.Email,
                VerifiedAt: DateTimeOffset.UtcNow
            )
        ), ct);

        return new VerifyEmailResult(true, null, null);
    }

    /// <inheritdoc/>
    public async Task<InitiateVerificationResult> ResendVerificationAsync(Guid principalId, CancellationToken ct)
    {
        var principal = await _dbContext.UserPrincipals
            .FirstOrDefaultAsync(p => p.Id == principalId, ct);

        if (principal == null)
        {
            _logger.LogWarning("Resend verification failed: principal {PrincipalId} not found", principalId);
            return new InitiateVerificationResult(false, "principal_not_found", "User principal not found", null);
        }

        if (principal.EmailVerifiedAtUtc.HasValue)
        {
            _logger.LogWarning("Resend verification failed: email already verified for principal {PrincipalId}", principalId);
            return new InitiateVerificationResult(false, "already_verified", "Email is already verified", null);
        }

        return await InitiateVerificationAsync(principalId, principal.Email, principal.FirstName, ct);
    }

    /// <inheritdoc/>
    public async Task<bool> IsEmailVerifiedAsync(Guid principalId, CancellationToken ct)
    {
        var principal = await _dbContext.UserPrincipals
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == principalId, ct);

        return principal?.EmailVerifiedAtUtc.HasValue == true;
    }
}
