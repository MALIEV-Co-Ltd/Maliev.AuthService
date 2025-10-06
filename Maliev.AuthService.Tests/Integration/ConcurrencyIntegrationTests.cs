using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Maliev.AuthService.Tests.Contract;
using Xunit;

namespace Maliev.AuthService.Tests.Integration;

/// <summary>
/// Integration tests for concurrency control using optimistic locking.
/// Verifies that concurrent token operations are handled correctly.
/// </summary>
[Trait("Category", "Integration")]
public class ConcurrencyIntegrationTests : IntegrationTestBase
{
    [Fact]
    public async Task RefreshToken_ConcurrentRequests_OnlyOneSucceeds()
    {
        // Test that concurrent refresh attempts with same token only allow one
        // This will FAIL until implementation

        // Arrange
        var loginRequest = new { username = "customer@example.com", password = "Password123!", user_type = "customer" };
        var loginResponse = await Client!.PostAsJsonAsync("/auth/login", loginRequest);
        var loginContent = await loginResponse.Content.ReadFromJsonAsync<LoginResponse>();

        var refreshRequest = new { refresh_token = loginContent!.RefreshToken };

        // Act - Concurrent refresh attempts
        var task1 = Client!.PostAsJsonAsync("/auth/refresh", refreshRequest);
        var task2 = Client!.PostAsJsonAsync("/auth/refresh", refreshRequest);

        var responses = await Task.WhenAll(task1, task2);

        // Assert - One succeeds (200), one detects reuse (401)
        var successCount = responses.Count(r => r.StatusCode == HttpStatusCode.OK);
        var reuseDetectedCount = responses.Count(r => r.StatusCode == HttpStatusCode.Unauthorized);

        successCount.Should().Be(1);
        reuseDetectedCount.Should().Be(1);

        // TODO: Verify optimistic locking prevented double-rotation
        // TODO: Verify token family is invalidated due to reuse detection
    }

    [Fact]
    public async Task TokenRevocation_ConcurrentRevocations_BothSucceed()
    {
        await Task.CompletedTask;
        // Test that concurrent revocations of same token don't cause conflicts
        // This will FAIL until implementation

        // TODO: Login, then concurrently revoke same token twice
        // TODO: Both should return 204 (idempotent operation)
    }
}
