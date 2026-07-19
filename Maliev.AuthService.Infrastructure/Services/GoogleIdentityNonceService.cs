using System.Security.Cryptography;
using System.Text;
using Maliev.AuthService.Application.Identity;
using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Domain.Entities;
using Maliev.AuthService.Infrastructure.DbContexts;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace Maliev.AuthService.Infrastructure.Services;

/// <summary>
/// Persists only nonce hashes and consumes them with one atomic database delete.
/// </summary>
public sealed class GoogleIdentityNonceService(
    AuthDbContext dbContext,
    IConfiguration configuration,
    TimeProvider timeProvider) : IGoogleIdentityNonceService
{
    private readonly TimeSpan _lifetime = TimeSpan.FromMinutes(Math.Clamp(
        configuration.GetValue("GoogleIdentity:NonceLifetimeMinutes", 10),
        1,
        15));

    /// <inheritdoc />
    public async Task<GoogleIdentityNonceIssue> IssueAsync(
        string serviceName,
        string application,
        GoogleIdentityExchangeType exchangeType,
        CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow().UtcDateTime;
        await dbContext.GoogleIdentityNonces
            .Where(existing => existing.ExpiresAtUtc <= now)
            .ExecuteDeleteAsync(cancellationToken);

        var nonce = ToBase64Url(RandomNumberGenerator.GetBytes(32));
        var record = new GoogleIdentityNonce
        {
            Id = Guid.NewGuid(),
            NonceHash = Hash(nonce),
            ServiceName = Normalize(serviceName),
            Application = Normalize(application),
            ExchangeType = Normalize(exchangeType.ToString()),
            CreatedAtUtc = now,
            ExpiresAtUtc = now.Add(_lifetime)
        };
        dbContext.GoogleIdentityNonces.Add(record);
        await dbContext.SaveChangesAsync(cancellationToken);
        return new GoogleIdentityNonceIssue(record.Id, nonce, record.ExpiresAtUtc);
    }

    /// <inheritdoc />
    public async Task<bool> ConsumeAsync(
        string nonce,
        string serviceName,
        string application,
        GoogleIdentityExchangeType exchangeType,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(nonce))
        {
            return false;
        }

        var hash = Hash(nonce);
        var caller = Normalize(serviceName);
        var applicationSelector = Normalize(application);
        var type = Normalize(exchangeType.ToString());
        var now = timeProvider.GetUtcNow().UtcDateTime;
        var deleted = await dbContext.GoogleIdentityNonces
            .Where(existing =>
                existing.NonceHash == hash &&
                existing.ServiceName == caller &&
                existing.Application == applicationSelector &&
                existing.ExchangeType == type &&
                existing.ExpiresAtUtc > now)
            .ExecuteDeleteAsync(cancellationToken);
        return deleted == 1;
    }

    private static string Hash(string nonce) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(nonce)));

    private static string Normalize(string value) => value.Trim().ToLowerInvariant();

    private static string ToBase64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
