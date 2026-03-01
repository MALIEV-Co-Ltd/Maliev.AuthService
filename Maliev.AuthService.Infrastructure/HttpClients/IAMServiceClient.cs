using System.Net.Http.Json;
using Maliev.AuthService.Application.DTOs.IAM;
using Maliev.AuthService.Application.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Maliev.AuthService.Infrastructure.HttpClients;

/// <summary>
/// HTTP client implementation for the IAM service permission resolution.
/// </summary>
public class IAMServiceClient : IIAMServiceClient
{
    private static readonly System.Text.Json.JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = null // PascalCase (default) — IAM Service API v1 requires PascalCase
    };

    private readonly HttpClient _httpClient;
    private readonly ILogger<IAMServiceClient> _logger;
    private readonly Histogram<double> _resolutionLatency;
    private readonly Counter<long> _resolutionErrors;
    private readonly KeyValuePair<string, object?>[] _defaultTags;

    /// <summary>
    /// Initializes a new instance of the <see cref="IAMServiceClient"/> class.
    /// </summary>
    /// <param name="httpClient">The HTTP client.</param>
    /// <param name="meterFactory">The meter factory for metrics.</param>
    /// <param name="configuration">The configuration.</param>
    /// <param name="logger">The logger.</param>
    public IAMServiceClient(HttpClient httpClient, IMeterFactory meterFactory, IConfiguration configuration, ILogger<IAMServiceClient> logger)
    {
        _httpClient = httpClient;
        _logger = logger;

        var serviceName = configuration["Service:Name"] ?? "AuthService";
        var meter = meterFactory.Create($"{serviceName.ToLower()}-meter");

        _defaultTags = new[]
        {
            new KeyValuePair<string, object?>("service_name", serviceName),
            new KeyValuePair<string, object?>("version", configuration["Service:Version"] ?? "1.0.0"),
            new KeyValuePair<string, object?>("region", configuration["Service:Region"] ?? "global"),
            new KeyValuePair<string, object?>("environment", configuration["ASPNETCORE_ENVIRONMENT"] ?? "Production")
        };

        _resolutionLatency = meter.CreateHistogram<double>("auth.iam.resolution_latency", "ms", "Latency of IAM permission resolution");
        _resolutionErrors = meter.CreateCounter<long>("auth.iam.resolution_errors", "count", "Number of failed IAM permission resolution attempts");
    }

    /// <inheritdoc/>
    public async Task<PermissionResolutionResponse> ResolvePermissionsAsync(
        Guid principalId,
        CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        try
        {
            var request = new PermissionResolutionRequest { PrincipalId = principalId.ToString() };
            var response = await _httpClient.PostAsJsonAsync("/iam/v1/auth/resolve-permissions", request, JsonOptions, cancellationToken);

            stopwatch.Stop();

            var tags = new TagList();
            foreach (var tag in _defaultTags) tags.Add(tag);
            _resolutionLatency.Record(stopwatch.Elapsed.TotalMilliseconds, tags);

            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<PermissionResolutionResponse>(cancellationToken: cancellationToken);
                if (result != null)
                {
                    _logger.LogInformation("Successfully resolved {PermCount} permissions and {RoleCount} roles for principal {PrincipalId} in {ElapsedMs}ms",
                        result.Permissions.Count, result.Roles.Count, principalId, stopwatch.ElapsedMilliseconds);
                    return result;
                }
            }

            _logger.LogWarning("Failed to resolve permissions for principal {PrincipalId}. Status: {StatusCode}", principalId, response.StatusCode);

            var errorTags = new TagList();
            foreach (var tag in _defaultTags) errorTags.Add(tag);
            errorTags.Add("reason", "http_error");
            errorTags.Add("status_code", (int)response.StatusCode);
            _resolutionErrors.Add(1, errorTags);
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            _logger.LogError(ex, "Error calling IAM service for principal {PrincipalId} after {ElapsedMs}ms", principalId, stopwatch.ElapsedMilliseconds);

            var errorTags = new TagList();
            foreach (var tag in _defaultTags) errorTags.Add(tag);
            errorTags.Add("reason", "exception");
            errorTags.Add("exception_type", ex.GetType().Name);
            _resolutionErrors.Add(1, errorTags);
        }

        return new PermissionResolutionResponse
        {
            PrincipalId = principalId,
            Permissions = new List<string>(),
            Roles = new List<string>(),
            ResolvedAt = DateTime.UtcNow
        };
    }
}
