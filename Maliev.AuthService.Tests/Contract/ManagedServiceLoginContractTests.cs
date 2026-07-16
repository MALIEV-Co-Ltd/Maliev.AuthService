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
    private const string AuthSecret = "auth-service-secret-with-at-least-32-random-looking-bytes";
    private const string ContactSecret = "contact-service-secret-with-at-least-32-random-looking-bytes";
    private const string SearchSecret = "search-service-secret-with-at-least-32-random-looking-bytes";
    private const string RegistrySecret = "registry-service-secret-with-at-least-32-random-looking-bytes";

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
    public async Task ServiceLogin_ManagedServiceCredentials_AuthenticateWithCanonicalClaims()
    {
        await SeedCanonicalManagedCredentialsAsync();
        using var client = factory.CreateClient();

        var auth = await LoginAsync(client, "service-auth-service", AuthSecret, "127.0.13.1");
        var contact = await LoginAsync(client, "service-contact-service", ContactSecret, "127.0.13.2");
        var search = await LoginAsync(client, "service-search-service", SearchSecret, "127.0.13.3");
        var registry = await LoginAsync(client, "service-registry-service", RegistrySecret, "127.0.13.4");

        Assert.Equal(HttpStatusCode.OK, auth.StatusCode);
        Assert.Equal(HttpStatusCode.OK, contact.StatusCode);
        Assert.Equal(HttpStatusCode.OK, search.StatusCode);
        Assert.Equal(HttpStatusCode.OK, registry.StatusCode);

        await AssertCanonicalServiceTokenAsync(
            search,
            TestWebApplicationFactory.SearchServiceIamPrincipalId,
            "service-search-service",
            "SearchService",
            "roles.workloads.search-service.v1");
        await AssertCanonicalServiceTokenAsync(
            registry,
            TestWebApplicationFactory.RegistryServiceIamPrincipalId,
            "service-registry-service",
            "RegistryService",
            "roles.workloads.registry-service.v1");
    }

    [Theory]
    [InlineData("service-auth-service", ContactSecret, SearchSecret, RegistrySecret)]
    [InlineData("service-contact-service", AuthSecret, SearchSecret, RegistrySecret)]
    [InlineData("service-search-service", AuthSecret, ContactSecret, RegistrySecret)]
    [InlineData("service-registry-service", AuthSecret, ContactSecret, SearchSecret)]
    public async Task ServiceLogin_CrossedManagedServiceCredentials_AreUnauthorized(
        string clientId,
        string firstWrongSecret,
        string secondWrongSecret,
        string thirdWrongSecret)
    {
        await SeedCanonicalManagedCredentialsAsync();
        using var client = factory.CreateClient();

        var first = await LoginAsync(client, clientId, firstWrongSecret, "127.0.14.1");
        var second = await LoginAsync(client, clientId, secondWrongSecret, "127.0.14.2");
        var third = await LoginAsync(client, clientId, thirdWrongSecret, "127.0.14.3");

        Assert.Equal(HttpStatusCode.Unauthorized, first.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, second.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, third.StatusCode);
    }

    private async Task SeedCanonicalManagedCredentialsAsync()
    {
        await SeedManagedCredentialAsync(
            "service-auth-service",
            "auth-service",
            "roles.workloads.auth-service.v1",
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            "AuthService",
            true,
            (AuthSecret, ServiceCredentialVersionStatus.Active, DateTimeOffset.UtcNow.AddHours(1), null));
        await SeedManagedCredentialAsync(
            "service-contact-service",
            "contact-service",
            "roles.workloads.contact-service.v1",
            Guid.Parse("12121212-1212-1212-1212-121212121212"),
            "ContactService",
            true,
            (ContactSecret, ServiceCredentialVersionStatus.Active, DateTimeOffset.UtcNow.AddHours(1), null));
        await SeedManagedCredentialAsync(
            "service-search-service",
            "search-service",
            "roles.workloads.search-service.v1",
            TestWebApplicationFactory.SearchServiceIamPrincipalId,
            "SearchService",
            true,
            (SearchSecret, ServiceCredentialVersionStatus.Active, DateTimeOffset.UtcNow.AddHours(1), null));
        await SeedManagedCredentialAsync(
            "service-registry-service",
            "registry-service",
            "roles.workloads.registry-service.v1",
            TestWebApplicationFactory.RegistryServiceIamPrincipalId,
            "RegistryService",
            true,
            (RegistrySecret, ServiceCredentialVersionStatus.Active, DateTimeOffset.UtcNow.AddHours(1), null));
    }

    private static async Task AssertCanonicalServiceTokenAsync(
        HttpResponseMessage response,
        Guid principalId,
        string clientId,
        string serviceName,
        string roleId)
    {
        var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var token = new JwtSecurityTokenHandler().ReadJwtToken(
            payload.RootElement.GetProperty("access_token").GetString());
        Assert.Equal(principalId.ToString(), token.Subject);
        Assert.Equal(clientId, token.Claims.Single(claim => claim.Type == "client_id").Value);
        Assert.Equal(serviceName, token.Claims.Single(claim => claim.Type == "service_name").Value);
        Assert.Equal(
            ["iam.auth.check-permission"],
            token.Claims.Where(claim => claim.Type == "permissions").Select(claim => claim.Value));
        Assert.Equal(
            [roleId],
            token.Claims.Where(claim => claim.Type == "roles").Select(claim => claim.Value));
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
