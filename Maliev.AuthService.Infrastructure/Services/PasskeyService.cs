using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Application.DTOs.Response;
using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Domain.Entities;
using Maliev.AuthService.Infrastructure.DbContexts;
using Maliev.MessagingContracts;
using Maliev.MessagingContracts.Contracts.Auth;
using MassTransit;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Maliev.AuthService.Infrastructure.Services;

/// <summary>
/// Implements WebAuthn passkey registration, authentication, and credential management.
/// </summary>
public class PasskeyService : IPasskeyService
{
    private const int MaxPasskeysPerPrincipal = 10;
    private const int ChallengeTtlMinutes = 5;
    private const string ChallengeKeyPrefix = "passkey:challenge:";

    private readonly AuthDbContext _dbContext;
    private readonly IDistributedCache _cache;
    private readonly IPublishEndpoint _publishEndpoint;
    private readonly IConfiguration _configuration;
    private readonly ILogger<PasskeyService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="PasskeyService"/> class.
    /// </summary>
    /// <param name="dbContext">The database context.</param>
    /// <param name="cache">The distributed cache for challenge storage.</param>
    /// <param name="publishEndpoint">The publish endpoint for events.</param>
    /// <param name="configuration">The application configuration.</param>
    /// <param name="logger">The logger instance.</param>
    public PasskeyService(
        AuthDbContext dbContext,
        IDistributedCache cache,
        IPublishEndpoint publishEndpoint,
        IConfiguration configuration,
        ILogger<PasskeyService> logger)
    {
        _dbContext = dbContext;
        _cache = cache;
        _publishEndpoint = publishEndpoint;
        _configuration = configuration;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<PasskeyRegistrationBeginResponse> BeginRegistrationAsync(Guid principalId, CancellationToken ct)
    {
        var principal = await _dbContext.UserPrincipals
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == principalId, ct);

        if (principal == null)
        {
            throw new InvalidOperationException($"Principal {principalId} not found");
        }

        var challenge = RandomNumberGenerator.GetBytes(32);
        var challengeB64 = Base64UrlEncode(challenge);

        var cacheKey = $"{ChallengeKeyPrefix}{principalId}";
        var cacheOptions = new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(ChallengeTtlMinutes)
        };
        await _cache.SetStringAsync(cacheKey, challengeB64, cacheOptions, ct);

        _logger.LogInformation("Passkey registration challenge created for principal {PrincipalId}", principalId);

        var rpId = _configuration["Passkey:RpId"] ?? "localhost";
        var rpName = _configuration["Passkey:RpName"] ?? "MALIEV";
        var userIdBytes = Encoding.UTF8.GetBytes(principalId.ToString());
        var userIdB64 = Base64UrlEncode(userIdBytes);

        var pubKeyCredParams = JsonSerializer.SerializeToElement(new[]
        {
            new { type = "public-key", alg = -7 },
            new { type = "public-key", alg = -257 }
        });

        var authenticatorSelection = JsonSerializer.SerializeToElement(new
        {
            authenticatorAttachment = "platform",
            residentKey = "preferred",
            userVerification = "preferred"
        });

        var attestation = JsonSerializer.SerializeToElement("none");

        return new PasskeyRegistrationBeginResponse(
            RpId: rpId,
            RpName: rpName,
            UserId: userIdB64,
            UserName: principal.Email,
            UserDisplayName: $"{principal.FirstName} {principal.LastName}",
            Challenge: JsonSerializer.SerializeToElement(challengeB64),
            PubKeyCredParams: pubKeyCredParams,
            AuthenticatorSelection: authenticatorSelection,
            Attestation: attestation,
            Extensions: null);
    }

    /// <inheritdoc/>
    public async Task<PasskeyRegistrationCompleteResponse> CompleteRegistrationAsync(PasskeyRegistrationCompleteRequest request, CancellationToken ct)
    {
        var cacheKey = $"{ChallengeKeyPrefix}{request.PrincipalId}";
        var cachedChallenge = await _cache.GetStringAsync(cacheKey, ct);

        if (string.IsNullOrEmpty(cachedChallenge))
        {
            _logger.LogWarning("No active challenge found for principal {PrincipalId}", request.PrincipalId);
            return new PasskeyRegistrationCompleteResponse(false, "Challenge expired or not found");
        }

        var credentialExists = await _dbContext.PasskeyCredentials
            .AnyAsync(c => c.CredentialId == request.CredentialId, ct);

        if (credentialExists)
        {
            _logger.LogWarning("Duplicate credential ID {CredentialId}", request.CredentialId);
            return new PasskeyRegistrationCompleteResponse(false, "Credential already registered");
        }

        var credentialCount = await _dbContext.PasskeyCredentials
            .CountAsync(c => c.PrincipalId == request.PrincipalId, ct);

        if (credentialCount >= MaxPasskeysPerPrincipal)
        {
            _logger.LogWarning("Max passkeys reached for principal {PrincipalId}", request.PrincipalId);
            return new PasskeyRegistrationCompleteResponse(false, $"Maximum of {MaxPasskeysPerPrincipal} passkeys reached");
        }

        var credential = new PasskeyCredential
        {
            Id = Guid.NewGuid(),
            PrincipalId = request.PrincipalId,
            CredentialId = request.CredentialId,
            PublicKey = request.PublicKey,
            DeviceName = request.DeviceName,
            Aaguid = request.Aaguid,
            SignCount = 0,
            CreatedAtUtc = DateTime.UtcNow,
            LastUsedAtUtc = null
        };

        _dbContext.PasskeyCredentials.Add(credential);
        await _dbContext.SaveChangesAsync(ct);

        await _cache.RemoveAsync(cacheKey, ct);

        _logger.LogInformation("Passkey credential {CredentialId} registered for principal {PrincipalId}", request.CredentialId, request.PrincipalId);

        await _publishEndpoint.Publish(new PasskeyRegisteredEvent(
            MessageId: Guid.NewGuid(),
            MessageName: "PasskeyRegisteredEvent",
            MessageType: MessageType.Event,
            MessageVersion: "1.0.0",
            PublishedBy: "AuthService",
            ConsumedBy: new[] { "NotificationService" },
            CorrelationId: Guid.NewGuid(),
            CausationId: null,
            OccurredAtUtc: DateTimeOffset.UtcNow,
            IsPublic: false,
            Payload: new PasskeyRegisteredEventPayload(
                PrincipalId: request.PrincipalId,
                CredentialId: request.CredentialId,
                DeviceName: request.DeviceName,
                RegisteredAt: DateTimeOffset.UtcNow
            )
        ), ct);

        return new PasskeyRegistrationCompleteResponse(true, null);
    }

    /// <inheritdoc/>
    public async Task<PasskeyAuthBeginResponse> BeginAuthenticationAsync(Guid? principalId, CancellationToken ct)
    {
        var challenge = RandomNumberGenerator.GetBytes(32);
        var challengeB64 = Base64UrlEncode(challenge);

        var cacheKey = principalId.HasValue
            ? $"{ChallengeKeyPrefix}{principalId.Value}"
            : $"{ChallengeKeyPrefix}anonymous:{Guid.NewGuid()}";
        var cacheOptions = new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(ChallengeTtlMinutes)
        };
        await _cache.SetStringAsync(cacheKey, challengeB64, cacheOptions, ct);

        _logger.LogInformation("Passkey authentication challenge created for principal {PrincipalId}", principalId);

        var rpId = _configuration["Passkey:RpId"] ?? "localhost";

        if (principalId.HasValue)
        {
            var credentials = await _dbContext.PasskeyCredentials
                .AsNoTracking()
                .Where(c => c.PrincipalId == principalId.Value)
                .Select(c => new { c.CredentialId })
                .ToListAsync(ct);

            var allowCredentials = credentials.Select(c => new
            {
                type = "public-key",
                id = c.CredentialId
            }).ToArray();

            var allowCredentialsElement = JsonSerializer.SerializeToElement(allowCredentials);

            return new PasskeyAuthBeginResponse(
                RpId: rpId,
                Challenge: JsonSerializer.SerializeToElement(challengeB64),
                AllowCredentials: allowCredentialsElement,
                UserVerification: "preferred");
        }

        var emptyAllowCredentials = JsonSerializer.SerializeToElement(Array.Empty<object>());

        return new PasskeyAuthBeginResponse(
            RpId: rpId,
            Challenge: JsonSerializer.SerializeToElement(challengeB64),
            AllowCredentials: emptyAllowCredentials,
            UserVerification: "required");
    }

    /// <inheritdoc/>
    public async Task<PasskeyAuthCompleteResponse> CompleteAuthenticationAsync(PasskeyAuthCompleteRequest request, CancellationToken ct)
    {
        var credential = await _dbContext.PasskeyCredentials
            .FirstOrDefaultAsync(c => c.CredentialId == request.CredentialId, ct);

        if (credential == null)
        {
            _logger.LogWarning("Credential not found: {CredentialId}", request.CredentialId);
            return new PasskeyAuthCompleteResponse(false, "Credential not found", null, null);
        }

        var verified = VerifySignature(
            request.AuthenticatorData,
            request.ClientDataJson,
            request.Signature,
            credential.PublicKey);

        if (!verified)
        {
            _logger.LogWarning("Signature verification failed for credential {CredentialId}", request.CredentialId);
            return new PasskeyAuthCompleteResponse(false, "Invalid signature", null, null);
        }

        credential.SignCount++;
        credential.LastUsedAtUtc = DateTime.UtcNow;
        await _dbContext.SaveChangesAsync(ct);

        var principal = await _dbContext.UserPrincipals
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == credential.PrincipalId, ct);

        _logger.LogInformation("Passkey authentication successful for principal {PrincipalId}", credential.PrincipalId);

        return new PasskeyAuthCompleteResponse(true, null, credential.PrincipalId, principal?.Email);
    }

    /// <inheritdoc/>
    public async Task<PasskeyListResponse> ListCredentialsAsync(Guid principalId, CancellationToken ct)
    {
        var credentials = await _dbContext.PasskeyCredentials
            .AsNoTracking()
            .Where(c => c.PrincipalId == principalId)
            .OrderByDescending(c => c.CreatedAtUtc)
            .Select(c => new PasskeyCredentialListItem(
                c.Id,
                c.DeviceName,
                c.Aaguid,
                c.CreatedAtUtc,
                c.LastUsedAtUtc))
            .ToListAsync(ct);

        return new PasskeyListResponse(credentials);
    }

    /// <inheritdoc/>
    public async Task<bool> DeleteCredentialAsync(Guid credentialId, Guid principalId, CancellationToken ct)
    {
        var credential = await _dbContext.PasskeyCredentials
            .FirstOrDefaultAsync(c => c.Id == credentialId && c.PrincipalId == principalId, ct);

        if (credential == null)
        {
            _logger.LogWarning("Credential {CredentialId} not found for principal {PrincipalId}", credentialId, principalId);
            return false;
        }

        _dbContext.PasskeyCredentials.Remove(credential);
        await _dbContext.SaveChangesAsync(ct);

        _logger.LogInformation("Credential {CredentialId} deleted for principal {PrincipalId}", credentialId, principalId);

        return true;
    }

    private static bool VerifySignature(string authenticatorDataB64, string clientDataJsonB64, string signatureB64, string publicKeyPem)
    {
        try
        {
            var authenticatorData = Base64UrlDecode(authenticatorDataB64);
            var clientDataJson = Base64UrlDecode(clientDataJsonB64);
            var clientDataHash = SHA256.HashData(clientDataJson);
            var signedData = new byte[authenticatorData.Length + clientDataHash.Length];
            Buffer.BlockCopy(authenticatorData, 0, signedData, 0, authenticatorData.Length);
            Buffer.BlockCopy(clientDataHash, 0, signedData, authenticatorData.Length, clientDataHash.Length);
            var signature = Base64UrlDecode(signatureB64);

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(publicKeyPem);
            return ecdsa.VerifyData(signedData, signature, HashAlgorithmName.SHA256);
        }
        catch
        {
            return false;
        }
    }

    private static string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    private static byte[] Base64UrlDecode(string base64Url)
    {
        var padded = base64Url.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2:
                padded += "==";
                break;
            case 3:
                padded += "=";
                break;
        }

        return Convert.FromBase64String(padded);
    }
}
