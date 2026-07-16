using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Maliev.AuthService.Application.DTOs.IAM;
using Maliev.AuthService.Application.Interfaces;

namespace Maliev.AuthService.Infrastructure.HttpClients;

/// <summary>Calls IAM workload provisioning while preserving the employee authorization boundary.</summary>
public sealed class WorkloadIdentityIamClient(HttpClient httpClient) : IWorkloadIdentityIamClient
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };

    /// <inheritdoc/>
    public async Task<WorkloadPrincipalResponse> ProvisionAsync(
        string workloadId,
        ProvisionWorkloadPrincipalRequest request,
        string callerBearerToken,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(callerBearerToken);

        using var message = new HttpRequestMessage(
            HttpMethod.Put,
            $"/iam/v1/workload-principals/{Uri.EscapeDataString(workloadId)}")
        {
            Content = JsonContent.Create(request, options: JsonOptions)
        };
        message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", callerBearerToken);

        using var response = await httpClient.SendAsync(
            message,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<WorkloadPrincipalResponse>(
            JsonOptions,
            cancellationToken)
            ?? throw new HttpRequestException("IAM returned an empty workload principal response");
    }
}
