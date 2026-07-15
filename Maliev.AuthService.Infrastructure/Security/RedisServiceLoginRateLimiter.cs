using System.Net;
using System.Security.Cryptography;
using System.Text;
using Maliev.AuthService.Application.Interfaces;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace Maliev.AuthService.Infrastructure.Security;

/// <summary>
/// Uses Redis to atomically share service-login limits across replicas. The peer bucket uses the
/// socket peer address supplied by ASP.NET Core and never trusts forwarded headers implicitly.
/// A trusted ingress should provide the outer request-rate ceiling before traffic reaches this service.
/// </summary>
public sealed class RedisServiceLoginRateLimiter(
    IConnectionMultiplexer? redis,
    IOptions<ServiceLoginRateLimitOptions> options,
    ILogger<RedisServiceLoginRateLimiter> logger) : IServiceLoginRateLimiter
{
    private const string AcquireScript = """
        local peerCount = redis.call('INCR', KEYS[1])
        if peerCount == 1 then
            redis.call('PEXPIRE', KEYS[1], ARGV[1])
        end
        local clientCount = redis.call('INCR', KEYS[2])
        if clientCount == 1 then
            redis.call('PEXPIRE', KEYS[2], ARGV[1])
        end
        return {
            peerCount,
            redis.call('PTTL', KEYS[1]),
            clientCount,
            redis.call('PTTL', KEYS[2])
        }
        """;
    private readonly ServiceLoginRateLimitOptions _options = options.Value;

    /// <inheritdoc />
    public async Task<ServiceLoginRateLimitResult> TryAcquireAsync(
        string clientId,
        IPAddress? remoteIpAddress,
        CancellationToken cancellationToken = default)
    {
        if (redis is null || !redis.IsConnected)
        {
            return new ServiceLoginRateLimitResult(false, false, 0);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var keys = CreatePartitionKeys(clientId, remoteIpAddress);
        try
        {
            var result = (RedisResult[]?)await redis.GetDatabase().ScriptEvaluateAsync(
                AcquireScript,
                keys,
                [_options.WindowSeconds * 1000]);
            if (result is not { Length: 4 })
            {
                return new ServiceLoginRateLimitResult(false, false, 0);
            }

            var peerCount = (long)result[0];
            var peerRemainingMilliseconds = Math.Max(1, (long)result[1]);
            var clientCount = (long)result[2];
            var clientRemainingMilliseconds = Math.Max(1, (long)result[3]);
            var peerDenied = peerCount > _options.PeerPermitLimit;
            var clientDenied = clientCount > _options.ClientPermitLimit;
            var remainingMilliseconds = peerDenied && clientDenied
                ? Math.Max(peerRemainingMilliseconds, clientRemainingMilliseconds)
                : peerDenied
                    ? peerRemainingMilliseconds
                    : clientRemainingMilliseconds;
            return new ServiceLoginRateLimitResult(
                true,
                !peerDenied && !clientDenied,
                (int)Math.Ceiling(remainingMilliseconds / 1000d));
        }
        catch (RedisException exception)
        {
            logger.LogError(exception, "Redis service-login rate limiter is unavailable");
            return new ServiceLoginRateLimitResult(false, false, 0);
        }
        catch (ObjectDisposedException exception)
        {
            logger.LogError(exception, "Redis service-login rate limiter is unavailable");
            return new ServiceLoginRateLimitResult(false, false, 0);
        }
    }

    private static RedisKey[] CreatePartitionKeys(string clientId, IPAddress? remoteIpAddress)
    {
        var normalizedClientId = clientId.Trim().ToLowerInvariant();
        var normalizedAddress = remoteIpAddress?.MapToIPv6().ToString() ?? "unknown";
        return
        [
            CreateHashedKey("peer", normalizedAddress),
            CreateHashedKey("client", normalizedClientId)
        ];
    }

    private static RedisKey CreateHashedKey(string bucket, string value)
    {
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)))
            .ToLowerInvariant();
        return $"auth:{{service-login-rate}}:{bucket}:{digest}";
    }
}
