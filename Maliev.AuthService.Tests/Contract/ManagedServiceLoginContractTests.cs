using System.IdentityModel.Tokens.Jwt;
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

    [Fact]
    public async Task ServiceLogin_AuthContactAndSearchCredentials_AreIsolatedAndSearchClaimsAreCanonical()
    {
        const string authSecret = "auth-service-secret-with-at-least-32-random-looking-bytes";
        const string contactSecret = "contact-service-secret-with-at-least-32-random-looking-bytes";
        const string searchSecret = "search-service-secret-with-at-least-32-random-looking-bytes";
        await SeedManagedCredentialAsync(
            "service-auth-service",
            "auth-service",
            "roles.workloads.auth-service.v1",
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            "AuthService",
            true,
            (authSecret, ServiceCredentialVersionStatus.Active, DateTimeOffset.UtcNow.AddHours(1), null));
        await SeedManagedCredentialAsync(
            "service-contact-service",
            "contact-service",
            "roles.workloads.contact-service.v1",
            Guid.Parse("12121212-1212-1212-1212-121212121212"),
            "ContactService",
            true,
            (contactSecret, ServiceCredentialVersionStatus.Active, DateTimeOffset.UtcNow.AddHours(1), null));
        await SeedManagedCredentialAsync(
            "service-search-service",
            "search-service",
            "roles.workloads.search-service.v1",
            TestWebApplicationFactory.SearchServiceIamPrincipalId,
            "SearchService",
            true,
            (searchSecret, ServiceCredentialVersionStatus.Active, DateTimeOffset.UtcNow.AddHours(1), null));
        using var client = factory.CreateClient();

        var auth = await LoginAsync(client, "service-auth-service", authSecret, "127.0.13.1");
        var contact = await LoginAsync(client, "service-contact-service", contactSecret, "127.0.13.2");
        var search = await LoginAsync(client, "service-search-service", searchSecret, "127.0.13.3");
        var authClientWithContactSecret = await LoginAsync(
            client,
            "service-auth-service",
            contactSecret,
            "127.0.13.4");
        var authClientWithSearchSecret = await LoginAsync(
            client,
            "service-auth-service",
            searchSecret,
            "127.0.13.5");
        var contactClientWithAuthSecret = await LoginAsync(
            client,
            "service-contact-service",
            authSecret,
            "127.0.13.6");
        var contactClientWithSearchSecret = await LoginAsync(
            client,
            "service-contact-service",
            searchSecret,
            "127.0.13.7");
        var searchClientWithAuthSecret = await LoginAsync(
            client,
            "service-search-service",
            authSecret,
            "127.0.13.8");
        var searchClientWithContactSecret = await LoginAsync(
            client,
            "service-search-service",
            contactSecret,
            "127.0.13.9");

        Assert.Equal(HttpStatusCode.OK, auth.StatusCode);
        Assert.Equal(HttpStatusCode.OK, contact.StatusCode);
        Assert.Equal(HttpStatusCode.OK, search.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, authClientWithContactSecret.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, authClientWithSearchSecret.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, contactClientWithAuthSecret.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, contactClientWithSearchSecret.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, searchClientWithAuthSecret.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, searchClientWithContactSecret.StatusCode);

        var searchResponse = JsonDocument.Parse(await search.Content.ReadAsStringAsync());
        var searchToken = new JwtSecurityTokenHandler().ReadJwtToken(
            searchResponse.RootElement.GetProperty("access_token").GetString());
        Assert.Equal(TestWebApplicationFactory.SearchServiceIamPrincipalId.ToString(), searchToken.Subject);
        Assert.Equal(
            "service-search-service",
            searchToken.Claims.Single(claim => claim.Type == "client_id").Value);
        Assert.Equal(
            "SearchService",
            searchToken.Claims.Single(claim => claim.Type == "service_name").Value);
        Assert.Equal(
            ["iam.auth.check-permission"],
            searchToken.Claims.Where(claim => claim.Type == "permissions").Select(claim => claim.Value));
        Assert.Equal(
            ["roles.workloads.search-service.v1"],
            searchToken.Claims.Where(claim => claim.Type == "roles").Select(claim => claim.Value));
    }

    private static async Task<HttpResponseMessage> LoginAsync(
        HttpClient client,
        string secret,
        string ipAddress) =>
        await LoginAsync(client, "service-auth-service", secret, ipAddress);

    private static async Task<HttpResponseMessage> LoginAsync(
        HttpClient client,
        string clientId,
        string secret,
        string ipAddress)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/v1/service/login")
        {
            Content = JsonContent.Create(
                new ServiceLoginRequest
                {
                    ClientId = clientId,
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
        params (string Secret, ServiceCredentialVersionStatus Status, DateTimeOffset HardExpiry, DateTimeOffset? GraceExpiry)[] versions) =>
        await SeedManagedCredentialAsync(
            "service-auth-service",
            "auth-service",
            "roles.workloads.auth-service.v1",
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            "AuthService",
            logicalActive,
            versions);

    private async Task SeedManagedCredentialAsync(
        string clientId,
        string workloadId,
        string roleId,
        Guid principalId,
        string serviceName,
        bool logicalActive,
        params (string Secret, ServiceCredentialVersionStatus Status, DateTimeOffset HardExpiry, DateTimeOffset? GraceExpiry)[] versions)
    {
        await using var context = factory.CreateDbContext();
        var now = DateTimeOffset.UtcNow.AddMinutes(-1);
        var credential = new ServiceCredential
        {
            Id = Guid.NewGuid(),
            ClientId = clientId,
            PrincipalId = principalId,
            WorkloadId = workloadId,
            ProfileVersion = 1,
            RoleId = roleId,
            ClientSecretHash = Hash(versions[0].Secret),
            ServiceName = serviceName,
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
