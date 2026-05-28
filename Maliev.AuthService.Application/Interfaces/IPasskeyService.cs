using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Application.DTOs.Response;

namespace Maliev.AuthService.Application.Interfaces;

/// <summary>
/// Service for WebAuthn passkey registration, authentication, and management.
/// </summary>
public interface IPasskeyService
{
    /// <summary>
    /// Begins WebAuthn credential registration by generating a challenge and creation options.
    /// </summary>
    /// <param name="principalId">The principal for whom the passkey is being registered.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Credential creation options for the WebAuthn client.</returns>
    Task<PasskeyRegistrationBeginResponse> BeginRegistrationAsync(Guid principalId, CancellationToken ct);

    /// <summary>
    /// Completes WebAuthn credential registration by verifying the authenticator response and storing the credential.
    /// </summary>
    /// <param name="request">The registration completion request.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Registration result.</returns>
    Task<PasskeyRegistrationCompleteResponse> CompleteRegistrationAsync(PasskeyRegistrationCompleteRequest request, CancellationToken ct);

    /// <summary>
    /// Begins WebAuthn authentication by generating a challenge and credential request options.
    /// </summary>
    /// <param name="principalId">Optional principal ID to scope allowed credentials.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Credential request options for the WebAuthn client.</returns>
    Task<PasskeyAuthBeginResponse> BeginAuthenticationAsync(Guid? principalId, CancellationToken ct);

    /// <summary>
    /// Completes WebAuthn authentication by verifying the assertion signature.
    /// </summary>
    /// <param name="request">The authentication completion request.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Authentication result with principal information.</returns>
    Task<PasskeyAuthCompleteResponse> CompleteAuthenticationAsync(PasskeyAuthCompleteRequest request, CancellationToken ct);

    /// <summary>
    /// Lists all passkey credentials for a principal.
    /// </summary>
    /// <param name="principalId">The principal identifier.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>List of passkey credentials.</returns>
    Task<PasskeyListResponse> ListCredentialsAsync(Guid principalId, CancellationToken ct);

    /// <summary>
    /// Deletes a passkey credential.
    /// </summary>
    /// <param name="credentialId">The credential identifier.</param>
    /// <param name="principalId">The principal who owns the credential.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>True if the credential was deleted; false otherwise.</returns>
    Task<bool> DeleteCredentialAsync(Guid credentialId, Guid principalId, CancellationToken ct);
}
