using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Domain.Entities;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

[Collection("AuthService Collection")]
public sealed class ManagedServiceLoginContractTests(TestWebApplicationFactory factory) : IAsyncLifetime
{
    public Task InitializeAsync() => factory.CleanDatabaseAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task ServiceLogin_ActiveAndUnexpiredGraceVersions_BothAuthenticate()
    {
        const string activeSecret = "active-secret-with-at-least-32-random-looking-bytes";
        const string graceSecret = "grace-secret-with-at-least-32-random-looking-bytes";
        await SeedManagedCredentialAsync(
            true,
            (activeSecret, ServiceCredentialVersionStatus.Active, DateTimeOffset.UtcNow.AddHours(1), null),
            (graceSecret, ServiceCredentialVersionStatus.Grace, DateTimeOffset.UtcNow.AddHours(1), DateTimeOffset.UtcNow.AddMinutes(5)));
        using var client = factory.CreateClient();

        var active = await LoginAsync(client, activeSecret, "127.0.10.1");
        var grace = await LoginAsync(client, graceSecret, "127.0.10.2");

        Assert.Equal(HttpStatusCode.OK, active.StatusCode);
        Assert.Equal(HttpStatusCode.OK, grace.StatusCode);
    }

    [Theory]
    [InlineData(ServiceCredentialVersionStatus.Pending, true)]
    [InlineData(ServiceCredentialVersionStatus.Revoked, true)]
    [InlineData(ServiceCredentialVersionStatus.Active, false)]
    public async Task ServiceLogin_IneligibleVersionOrLogicalRevoke_IsUnauthorized(
        ServiceCredentialVersionStatus status,
        bool logicalActive)
    {
        const string secret = "ineligible-secret-with-at-least-32-random-looking-bytes";
        await SeedManagedCredentialAsync(
            logicalActive,
            (secret, status, DateTimeOffset.UtcNow.AddHours(1), null));
        using var client = factory.CreateClient();

        var response = await LoginAsync(client, secret, "127.0.11.1");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ServiceLogin_ExpiredActiveVersion_IsUnauthorized()
    {
        const string secret = "expired-secret-with-at-least-32-random-looking-bytes";
        await SeedManagedCredentialAsync(
            true,
            (secret, ServiceCredentialVersionStatus.Active, DateTimeOffset.UtcNow.AddSeconds(-1), null));
        using var client = factory.CreateClient();

        var response = await LoginAsync(client, secret, "127.0.12.1");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static async Task<HttpResponseMessage> LoginAsync(
        HttpClient client,
        string secret,
        string ipAddress)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/v1/service/login")
        {
            Content = JsonContent.Create(
                new ServiceLoginRequest
                {
                    ClientId = "service-auth-managed",
                    ClientSecret = secret
                },
                options: new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
                })
        };
        request.Headers.Add("X-Test-Client-IP", ipAddress);
        return await client.SendAsync(request);
    }

    private async Task SeedManagedCredentialAsync(
        bool logicalActive,
        params (string Secret, ServiceCredentialVersionStatus Status, DateTimeOffset HardExpiry, DateTimeOffset? GraceExpiry)[] versions)
    {
        await using var context = factory.CreateDbContext();
        var now = DateTimeOffset.UtcNow.AddMinutes(-1);
        var credential = new ServiceCredential
        {
            Id = Guid.NewGuid(),
            ClientId = "service-auth-managed",
            PrincipalId = Guid.Parse("11111111-1111-1111-1111-111111111111"),
            WorkloadId = "auth",
            ProfileVersion = 1,
            RoleId = "roles.workload.auth",
            ClientSecretHash = Hash(versions[0].Secret),
            ServiceName = "Auth Service",
            IsActive = logicalActive,
            RevokedAt = logicalActive ? null : DateTimeOffset.UtcNow,
            CreatedAt = now.UtcDateTime,
            UpdatedAt = now.UtcDateTime
        };
        context.ServiceCredentials.Add(credential);
        for (var index = 0; index < versions.Length; index++)
        {
            var version = versions[index];
            context.ServiceCredentialVersions.Add(new ServiceCredentialVersion
            {
                Id = Guid.NewGuid(),
                ServiceCredentialId = credential.Id,
                Version = index + 1,
                SecretHash = Hash(version.Secret),
                Status = version.Status,
                CreatedAt = now,
                ActivatedAt = version.Status is ServiceCredentialVersionStatus.Active or ServiceCredentialVersionStatus.Grace
                    ? now
                    : null,
                GraceExpiresAt = version.GraceExpiry,
                HardExpiresAt = version.HardExpiry,
                RevokedAt = version.Status == ServiceCredentialVersionStatus.Revoked
                    ? DateTimeOffset.UtcNow
                    : null
            });
        }

        await context.SaveChangesAsync();
    }

    private static string Hash(string secret) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));
}
