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
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };
    private readonly HttpClient _httpClient;
    private readonly ITokenIssuanceCapabilitySigner _signer;
    private readonly ILogger<TokenIssuancePermissionClient> _logger;

    /// <summary>Initializes the isolated IAM client.</summary>
    /// <param name="httpClient">The dedicated HTTP transport.</param>
    /// <param name="signer">The Auth-only capability signer.</param>
    /// <param name="logger">The client logger.</param>
    public TokenIssuancePermissionClient(
        HttpClient httpClient,
        ITokenIssuanceCapabilitySigner signer,
        ILogger<TokenIssuancePermissionClient> logger)
    {
        _httpClient = httpClient;
        _signer = signer;
        _logger = logger;
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

        var result = await response.Content.ReadFromJsonAsync<PermissionResolutionResponse>(
            JsonOptions,
            cancellationToken);
        if (result is null)
        {
            throw new HttpRequestException("IAM token-issuance permission resolution returned an empty response.");
        }

        if (result.PrincipalId != principalId)
        {
            throw new HttpRequestException("IAM token-issuance permission resolution returned a different principal.");
        }

        return result;
    }
}
