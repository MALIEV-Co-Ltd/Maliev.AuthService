using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Maliev.AuthService.Infrastructure.HttpClients;
using Maliev.AuthService.Infrastructure.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public sealed class TokenIssuancePermissionClientTests
{
    private static readonly Guid PrincipalId = Guid.Parse("11111111-1111-1111-1111-111111111111");

    [Fact]
    public async Task ResolvePermissionsAsync_ValidResponse_UsesOnlyAdditiveRouteAndTargetCoupledToken()
    {
        HttpRequestMessage? captured = null;
        var signer = new RecordingSigner();
        using var httpClient = new HttpClient(new DelegatingTestHandler(async (request, cancellationToken) =>
        {
            captured = request;
            var body = await request.Content!.ReadAsStringAsync(cancellationToken);
            using var json = JsonDocument.Parse(body);
            Assert.Equal(["principalId"], json.RootElement.EnumerateObject().Select(property => property.Name));
            Assert.Equal(PrincipalId.ToString("D"), json.RootElement.GetProperty("principalId").GetString());
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(new
                {
                    principalId = PrincipalId,
                    permissions = new[] { "customer.customers.read" },
                    roles = new[] { "service.customer" },
                    resolvedAt = DateTime.UtcNow,
                    cacheUntil = (DateTime?)null
                })
            };
        }))
        {
            BaseAddress = new Uri("https://iam.test"),
            Timeout = TimeSpan.FromSeconds(10)
        };
        var client = new TokenIssuancePermissionClient(httpClient, signer, NullLogger<TokenIssuancePermissionClient>.Instance);

        var response = await client.ResolvePermissionsAsync(PrincipalId, CancellationToken.None);

        Assert.NotNull(captured);
        Assert.Equal(HttpMethod.Post, captured.Method);
        Assert.Equal("/iam/v1/auth/token-issuance/resolve-permissions", captured.RequestUri!.AbsolutePath);
        Assert.Equal("Bearer", captured.Headers.Authorization!.Scheme);
        Assert.Equal("capability-token", captured.Headers.Authorization.Parameter);
        Assert.Equal(PrincipalId, signer.TargetPrincipalId);
        Assert.Equal(PrincipalId, response.PrincipalId);
        Assert.Equal(["customer.customers.read"], response.Permissions);
        Assert.Equal(["service.customer"], response.Roles);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task ResolvePermissionsAsync_NonSuccess_Throws(HttpStatusCode statusCode)
    {
        var client = CreateClient((_, _) => Task.FromResult(new HttpResponseMessage(statusCode)));

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.ResolvePermissionsAsync(PrincipalId, CancellationToken.None));
    }

    [Fact]
    public async Task ResolvePermissionsAsync_MalformedResponse_Throws()
    {
        var client = CreateClient((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{not-json")
        }));

        await Assert.ThrowsAnyAsync<Exception>(() =>
            client.ResolvePermissionsAsync(PrincipalId, CancellationToken.None));
    }

    [Fact]
    public async Task ResolvePermissionsAsync_MismatchedPrincipal_Throws()
    {
        var client = CreateClient((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new
            {
                principalId = Guid.NewGuid(),
                permissions = Array.Empty<string>(),
                roles = Array.Empty<string>(),
                resolvedAt = DateTime.UtcNow
            })
        }));

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.ResolvePermissionsAsync(PrincipalId, CancellationToken.None));
    }

    [Fact]
    public async Task ResolvePermissionsAsync_CallerCancellation_Propagates()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var client = CreateClient((_, token) => Task.FromCanceled<HttpResponseMessage>(token));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            client.ResolvePermissionsAsync(PrincipalId, cancellation.Token));
    }

    [Fact]
    public async Task ResolvePermissionsAsync_HttpTimeout_ThrowsWithoutCancellingCallerToken()
    {
        using var httpClient = new HttpClient(new DelegatingTestHandler(
            async (_, token) =>
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                return new HttpResponseMessage(HttpStatusCode.OK);
            }))
        {
            BaseAddress = new Uri("https://iam.test"),
            Timeout = TimeSpan.FromMilliseconds(20)
        };
        var client = new TokenIssuancePermissionClient(
            httpClient,
            new RecordingSigner(),
            NullLogger<TokenIssuancePermissionClient>.Instance);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            client.ResolvePermissionsAsync(PrincipalId, CancellationToken.None));
    }

    private static TokenIssuancePermissionClient CreateClient(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> sendAsync)
    {
        var httpClient = new HttpClient(new DelegatingTestHandler(sendAsync))
        {
            BaseAddress = new Uri("https://iam.test"),
            Timeout = TimeSpan.FromSeconds(10)
        };
        return new TokenIssuancePermissionClient(
            httpClient,
            new RecordingSigner(),
            NullLogger<TokenIssuancePermissionClient>.Instance);
    }

    private sealed class RecordingSigner : ITokenIssuanceCapabilitySigner
    {
        public Guid? TargetPrincipalId { get; private set; }

        public string CreateCapability(Guid targetPrincipalId)
        {
            TargetPrincipalId = targetPrincipalId;
            return "capability-token";
        }
    }

    private sealed class DelegatingTestHandler(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> sendAsync) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) => sendAsync(request, cancellationToken);
    }
}
