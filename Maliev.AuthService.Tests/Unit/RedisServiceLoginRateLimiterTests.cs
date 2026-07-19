using System.Net;
using Maliev.AuthService.Infrastructure.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public sealed class RedisServiceLoginRateLimiterTests
{
    [Fact]
    public async Task TryAcquireAsync_WithoutRedis_FailsClosed()
    {
        var limiter = new RedisServiceLoginRateLimiter(
            null,
            Options.Create(new ServiceLoginRateLimitOptions()),
            NullLogger<RedisServiceLoginRateLimiter>.Instance);

        var result = await limiter.TryAcquireAsync(
            "service-dev-customer-api",
            IPAddress.Loopback);

        Assert.False(result.IsAvailable);
        Assert.False(result.IsAllowed);
    }
}
