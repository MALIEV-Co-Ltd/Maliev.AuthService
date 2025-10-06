using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Xunit;

namespace Maliev.AuthService.Tests.Integration;

/// <summary>
/// Integration tests for rate limiting functionality.
/// Verifies that excessive login attempts are throttled.
/// </summary>
[Trait("Category", "Integration")]
public class RateLimitingIntegrationTests : IntegrationTestBase
{
    [Fact]
    public async Task Login_ExceedingRateLimit_Returns429TooManyRequests()
    {
        // Arrange
        var request = new
        {
            username = "attacker@example.com",
            password = "WrongPassword",
            user_type = "customer"
        };

        // Act - Make 6 failed login attempts (limit is 5 per spec)
        HttpResponseMessage? lastResponse = null;
        for (int i = 0; i < 6; i++)
        {
            lastResponse = await Client!.PostAsJsonAsync("/auth/login", request);
        }

        // Assert - This will FAIL until implementation
        lastResponse!.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);

        // TODO: Verify rate limit headers are present (X-RateLimit-Limit, X-RateLimit-Remaining)
    }

    [Fact]
    public async Task Login_WithinRateLimit_AllowsRequests()
    {
        await Task.CompletedTask;
        // Test that requests within the limit are allowed
        // This will FAIL until implementation

        // TODO: Make 4 failed attempts -> Should all return 401
        // TODO: 5th attempt -> Should return 401
        // TODO: 6th attempt -> Should return 429
    }
}
