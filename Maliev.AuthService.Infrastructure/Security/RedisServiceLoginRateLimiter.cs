using System.Net;
using System.Security.Cryptography;
using System.Text;
using Maliev.AuthService.Application.Interfaces;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace Maliev.AuthService.Infrastructure.Security;

/// <summary>
/// Uses Redis to atomically share service-login limits across replicas.
/// </summary>
public sealed class RedisServiceLoginRateLimiter(
    IConnectionMultiplexer? redis,
    IOptions<ServiceLoginRateLimitOptions> options,
    ILogger<RedisServiceLoginRateLimiter> logger) : IServiceLoginRateLimiter
{
    private const string AcquireScript = """
        local count = redis.call('INCR', KEYS[1])
        if count == 1 then
            redis.call('PEXPIRE', KEYS[1], ARGV[1])
        end
        return { count, redis.call('PTTL', KEYS[1]) }
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
        var key = CreatePartitionKey(clientId, remoteIpAddress);
        try
        {
            var result = (RedisResult[]?)await redis.GetDatabase().ScriptEvaluateAsync(
                AcquireScript,
                [key],
                [_options.WindowSeconds * 1000]);
            if (result is not { Length: 2 })
            {
                return new ServiceLoginRateLimitResult(false, false, 0);
            }

            var count = (long)result[0];
            var remainingMilliseconds = Math.Max(1, (long)result[1]);
            return new ServiceLoginRateLimitResult(
                true,
                count <= _options.PermitLimit,
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

    private static RedisKey CreatePartitionKey(string clientId, IPAddress? remoteIpAddress)
    {
        var normalizedClientId = clientId.Trim().ToLowerInvariant();
        var normalizedAddress = remoteIpAddress?.MapToIPv6().ToString() ?? "unknown";
        var partition = Encoding.UTF8.GetBytes($"{normalizedClientId}\n{normalizedAddress}");
        var digest = Convert.ToHexString(SHA256.HashData(partition)).ToLowerInvariant();
        return $"auth:service-login-rate:{digest}";
    }
}
