using System.Security.Cryptography;
using System.Text;
using Maliev.AuthService.Domain.Entities;
using Maliev.AuthService.Infrastructure.DbContexts;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Maliev.AuthService.Infrastructure.Security;

/// <summary>
/// Persists only hashes of browser-visible ceremony values and consumes flows with one atomic delete.
/// </summary>
public sealed class PasskeyCeremonyStore(
    AuthDbContext dbContext,
    IOptions<PasskeyWebAuthnOptions> options,
    TimeProvider timeProvider) : IPasskeyCeremonyStore
{
    private readonly TimeSpan _lifetime = TimeSpan.FromMinutes(Math.Clamp(
        options.Value.CeremonyLifetimeMinutes,
        1,
        10));

    /// <inheritdoc />
    public async Task<PasskeyCeremonyIssue> IssueAsync(
        string serviceName,
        string application,
        UserType expectedUserType,
        string assertionOptionsJson,
        byte[] challenge,
        CancellationToken cancellationToken)
    {
        var caller = NormalizeBounded(serviceName, 128, nameof(serviceName));
        var audience = NormalizeBounded(application, 64, nameof(application));
        if (expectedUserType is not (UserType.Customer or UserType.Employee))
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedUserType),
                "A supported principal audience is required.");
        }

        if (string.IsNullOrWhiteSpace(assertionOptionsJson) || assertionOptionsJson.Length > 16_384)
        {
            throw new ArgumentException("Assertion options are required and must be bounded.", nameof(assertionOptionsJson));
        }

        if (challenge is not { Length: >= 32 and <= 64 })
        {
            throw new ArgumentException("A 32 to 64 byte challenge is required.", nameof(challenge));
        }

        var now = timeProvider.GetUtcNow().UtcDateTime;
        await dbContext.PasskeyAssertionCeremonies
            .Where(existing => existing.ExpiresAtUtc <= now)
            .ExecuteDeleteAsync(cancellationToken);

        var flowId = ToBase64Url(RandomNumberGenerator.GetBytes(32));
        var ceremony = new PasskeyAssertionCeremony
        {
            Id = Guid.NewGuid(),
            FlowIdHash = Hash(Encoding.UTF8.GetBytes(flowId)),
            ChallengeHash = Hash(challenge),
            AssertionOptionsJson = assertionOptionsJson,
            ServiceName = caller,
            Application = audience,
            ExpectedUserType = expectedUserType,
            CreatedAtUtc = now,
            ExpiresAtUtc = now.Add(_lifetime)
        };
        dbContext.PasskeyAssertionCeremonies.Add(ceremony);
        await dbContext.SaveChangesAsync(cancellationToken);
        return new PasskeyCeremonyIssue(flowId, ceremony.ExpiresAtUtc);
    }

    /// <inheritdoc />
    public async Task<PasskeyCeremonyState?> ConsumeAsync(
        string flowId,
        string serviceName,
        string application,
        CancellationToken cancellationToken)
    {
        if (!IsCanonicalFlowId(flowId))
        {
            return null;
        }

        string caller;
        string audience;
        try
        {
            caller = NormalizeBounded(serviceName, 128, nameof(serviceName));
            audience = NormalizeBounded(application, 64, nameof(application));
        }
        catch (ArgumentException)
        {
            return null;
        }

        var hash = Hash(Encoding.UTF8.GetBytes(flowId));
        var now = timeProvider.GetUtcNow().UtcDateTime;
        var ceremony = await dbContext.PasskeyAssertionCeremonies
            .AsNoTracking()
            .Where(existing =>
                existing.FlowIdHash == hash &&
                existing.ServiceName == caller &&
                existing.Application == audience &&
                existing.ExpiresAtUtc > now)
            .Select(existing => new
            {
                existing.Id,
                existing.AssertionOptionsJson,
                existing.ExpectedUserType
            })
            .SingleOrDefaultAsync(cancellationToken);
        if (ceremony is null)
        {
            return null;
        }

        var deleted = await dbContext.PasskeyAssertionCeremonies
            .Where(existing =>
                existing.Id == ceremony.Id &&
                existing.FlowIdHash == hash &&
                existing.ServiceName == caller &&
                existing.Application == audience &&
                existing.ExpiresAtUtc > now)
            .ExecuteDeleteAsync(cancellationToken);
        return deleted == 1
            ? new PasskeyCeremonyState(
                ceremony.AssertionOptionsJson,
                ceremony.ExpectedUserType)
            : null;
    }

    private static string NormalizeBounded(string value, int maximumLength, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("A non-empty boundary value is required.", parameterName);
        }

        var normalized = value.Trim().ToLowerInvariant();
        if (normalized.Length > maximumLength)
        {
            throw new ArgumentException("The boundary value exceeds its maximum length.", parameterName);
        }

        return normalized;
    }

    private static bool IsCanonicalFlowId(string value)
    {
        if (value is not { Length: 43 } ||
            value.Any(character =>
                !(character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_')))
        {
            return false;
        }

        try
        {
            var padded = value.Replace('-', '+').Replace('_', '/') + "=";
            var decoded = Convert.FromBase64String(padded);
            return decoded.Length == 32 && string.Equals(ToBase64Url(decoded), value, StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static string Hash(byte[] value) => Convert.ToHexString(SHA256.HashData(value));

    private static string ToBase64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
