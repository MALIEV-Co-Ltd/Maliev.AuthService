using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Maliev.AuthService.Application.DTOs.IAM;
using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Infrastructure.Security;
using Microsoft.Extensions.Logging;

namespace Maliev.AuthService.Infrastructure.HttpClients;

/// <summary>Calls IAM's isolated token-issuance permission-resolution endpoint.</summary>
public sealed class TokenIssuancePermissionClient : ITokenIssuancePermissionClient
{
    private const string Route = "/iam/v1/auth/token-issuance/resolve-permissions";
    private const string InvalidResponseMessage =
        "IAM token-issuance permission resolution returned an invalid response.";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };
    private readonly HttpClient _httpClient;
    private readonly ITokenIssuanceCapabilitySigner _signer;
    private readonly ILogger<TokenIssuancePermissionClient> _logger;
    private readonly TimeProvider _timeProvider;

    /// <summary>Initializes the isolated IAM client.</summary>
    /// <param name="httpClient">The dedicated HTTP transport.</param>
    /// <param name="signer">The Auth-only capability signer.</param>
    /// <param name="logger">The client logger.</param>
    /// <param name="timeProvider">The clock used to record when Auth observed the IAM response.</param>
    public TokenIssuancePermissionClient(
        HttpClient httpClient,
        ITokenIssuanceCapabilitySigner signer,
        ILogger<TokenIssuancePermissionClient> logger,
        TimeProvider timeProvider)
    {
        _httpClient = httpClient;
        _signer = signer;
        _logger = logger;
        _timeProvider = timeProvider;
    }

    /// <inheritdoc/>
    public async Task<PermissionResolutionResponse> ResolvePermissionsAsync(
        Guid principalId,
        CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfEqual(principalId, Guid.Empty);

        using var request = new HttpRequestMessage(HttpMethod.Post, Route)
        {
            Content = JsonContent.Create(
                new PermissionResolutionRequest { PrincipalId = principalId.ToString("D") },
                options: JsonOptions)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            _signer.CreateCapability(principalId));

        using var response = await _httpClient.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning(
                "IAM token-issuance permission resolution failed for principal {PrincipalId} with status {StatusCode}",
                principalId,
                (int)response.StatusCode);
            response.EnsureSuccessStatusCode();
        }

        TokenIssuancePermissionResponse? result;
        try
        {
            result = await response.Content.ReadFromJsonAsync<TokenIssuancePermissionResponse>(
                JsonOptions,
                cancellationToken);
        }
        catch (JsonException ex)
        {
            throw new HttpRequestException(InvalidResponseMessage, ex);
        }

        if (result is null)
        {
            throw new HttpRequestException("IAM token-issuance permission resolution returned an empty response.");
        }

        if (result.PrincipalId != principalId)
        {
            throw new HttpRequestException("IAM token-issuance permission resolution returned a different principal.");
        }

        if (result.Permissions is null ||
            result.Roles is null ||
            result.Permissions.Any(value => string.IsNullOrWhiteSpace(value)) ||
            result.Roles.Any(value => string.IsNullOrWhiteSpace(value)) ||
            result.FromCache ||
            result.ResourcePath is not null ||
            result.CacheUntil is not null)
        {
            throw new HttpRequestException(InvalidResponseMessage);
        }

        return new PermissionResolutionResponse
        {
            PrincipalId = result.PrincipalId,
            Permissions = result.Permissions,
            Roles = result.Roles,
            ResolvedAt = _timeProvider.GetUtcNow().UtcDateTime,
            CacheUntil = null
        };
    }

    private sealed record TokenIssuancePermissionResponse
    {
        public required Guid PrincipalId { get; init; }

        public required List<string> Permissions { get; init; }

        public required List<string> Roles { get; init; }

        public string? ResourcePath { get; init; }

        public DateTime? CacheUntil { get; init; }

        public required bool FromCache { get; init; }
    }
}
