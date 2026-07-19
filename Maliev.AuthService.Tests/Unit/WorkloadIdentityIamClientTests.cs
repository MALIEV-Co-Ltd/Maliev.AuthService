using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Maliev.AuthService.Application.DTOs.IAM;
using Maliev.AuthService.Infrastructure.HttpClients;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public sealed class WorkloadIdentityIamClientTests
{
    [Fact]
    public async Task ProvisionAsync_ForwardsOnlyCallerBearerAndExactSnakeCaseContract()
    {
        var handler = new RecordingHandler();
        using var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://iam.test") };
        var client = new WorkloadIdentityIamClient(httpClient);
        var operationId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

        var result = await client.ProvisionAsync(
            "auth-service",
            new ProvisionWorkloadPrincipalRequest { ProfileVersion = 1, OperationId = operationId },
            "employee-token");

        Assert.Equal("/iam/v1/workload-principals/auth-service", handler.RequestUri?.AbsolutePath);
        Assert.Equal("Bearer", handler.AuthorizationScheme);
        Assert.Equal("employee-token", handler.AuthorizationParameter);
        using var document = JsonDocument.Parse(Assert.IsType<string>(handler.Body));
        Assert.Equal(1, document.RootElement.GetProperty("profile_version").GetInt32());
        Assert.Equal(operationId, document.RootElement.GetProperty("operation_id").GetGuid());
        Assert.False(document.RootElement.TryGetProperty("ProfileVersion", out _));
        Assert.Equal("auth-service", result.WorkloadId);
        Assert.Equal("roles.workloads.auth-service.v1", result.RoleId);
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public Uri? RequestUri { get; private set; }

        public string? AuthorizationScheme { get; private set; }

        public string? AuthorizationParameter { get; private set; }

        public string? Body { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestUri = request.RequestUri;
            AuthorizationScheme = request.Headers.Authorization?.Scheme;
            AuthorizationParameter = request.Headers.Authorization?.Parameter;
            Body = await request.Content!.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(new
                {
                    workload_id = "auth-service",
                    principal_id = "11111111-1111-1111-1111-111111111111",
                    profile_version = 1,
                    role_id = "roles.workloads.auth-service.v1"
                })
            };
        }
    }
}
