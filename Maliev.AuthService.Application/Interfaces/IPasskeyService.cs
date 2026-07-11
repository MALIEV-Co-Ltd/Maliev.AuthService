using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Application.DTOs.Response;

namespace Maliev.AuthService.Application.Interfaces;

/// <summary>
/// Service for verified, caller-bound WebAuthn passkey authentication.
/// </summary>
public interface IPasskeyService
{
    /// <summary>
    /// Begins WebAuthn authentication by generating a challenge and credential request options.
    /// </summary>
    /// <param name="request">The server-owned application request.</param>
    /// <param name="serviceName">The authenticated service caller.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Credential request options, or <see langword="null"/> when unavailable.</returns>
    Task<PasskeyAuthBeginResponse?> BeginAuthenticationAsync(
        PasskeyAuthBeginRequest request,
        string serviceName,
        CancellationToken ct);

    /// <summary>
    /// Completes WebAuthn authentication by verifying the assertion signature.
    /// </summary>
    /// <param name="request">The authentication completion request.</param>
    /// <param name="serviceName">The authenticated service caller.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Authentication result with principal information.</returns>
    Task<PasskeyAuthCompleteResponse> CompleteAuthenticationAsync(
        PasskeyAuthCompleteRequest request,
        string serviceName,
        CancellationToken ct);
}
