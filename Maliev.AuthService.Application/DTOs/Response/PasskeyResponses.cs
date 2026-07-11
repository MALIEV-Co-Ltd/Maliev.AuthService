using System.Text.Json;

namespace Maliev.AuthService.Application.DTOs.Response;

/// <summary>
/// Response containing WebAuthn credential creation options for the client.
/// </summary>
/// <param name="RpId">Relying Party identifier.</param>
/// <param name="RpName">Relying Party display name.</param>
/// <param name="UserId">User ID for the credential.</param>
/// <param name="UserName">Username for the credential.</param>
/// <param name="UserDisplayName">Display name for the credential.</param>
/// <param name="Challenge">Base64URL-encoded challenge.</param>
/// <param name="PubKeyCredParams">Supported public key credential parameters.</param>
/// <param name="AuthenticatorSelection">Optional authenticator selection criteria.</param>
/// <param name="Attestation">Optional attestation preference.</param>
/// <param name="Extensions">Optional WebAuthn extensions.</param>
public record PasskeyRegistrationBeginResponse(
    string RpId,
    string RpName,
    string UserId,
    string UserName,
    string UserDisplayName,
    JsonElement Challenge,
    JsonElement PubKeyCredParams,
    JsonElement? AuthenticatorSelection,
    JsonElement? Attestation,
    JsonElement? Extensions);

/// <summary>
/// Result of passkey registration completion.
/// </summary>
/// <param name="Success">Whether registration succeeded.</param>
/// <param name="Error">Error message if registration failed.</param>
public record PasskeyRegistrationCompleteResponse(bool Success, string? Error);

/// <summary>
/// Response containing WebAuthn credential request options for authentication.
/// </summary>
/// <param name="FlowId">Opaque one-time ceremony identifier.</param>
/// <param name="ExpiresAtUtc">UTC ceremony expiration.</param>
/// <param name="RpId">Relying Party identifier.</param>
/// <param name="Challenge">Base64URL-encoded challenge.</param>
/// <param name="AllowCredentials">Allowed credentials for authentication.</param>
/// <param name="UserVerification">User verification requirement.</param>
/// <param name="Timeout">Browser ceremony timeout in milliseconds.</param>
public record PasskeyAuthBeginResponse(
    string FlowId,
    DateTime ExpiresAtUtc,
    string RpId,
    string Challenge,
    IReadOnlyList<PasskeyAllowedCredential> AllowCredentials,
    string UserVerification,
    ulong Timeout);

/// <summary>
/// An allowed public-key credential descriptor returned to the browser.
/// </summary>
/// <param name="Type">The WebAuthn credential type.</param>
/// <param name="Id">The Base64URL credential identifier.</param>
public sealed record PasskeyAllowedCredential(string Type, string Id);

/// <summary>
/// Result of passkey authentication completion.
/// </summary>
/// <param name="Success">Whether authentication succeeded.</param>
/// <param name="Error">Error message if authentication failed.</param>
/// <param name="PrincipalId">The authenticated principal ID.</param>
/// <param name="Email">The authenticated user's email.</param>
public record PasskeyAuthCompleteResponse(bool Success, string? Error, Guid? PrincipalId, string? Email);

/// <summary>
/// A single passkey credential in a list response.
/// </summary>
/// <param name="Id">Credential identifier.</param>
/// <param name="DeviceName">Human-readable device name.</param>
/// <param name="Aaguid">Authenticator Attestation GUID.</param>
/// <param name="CreatedAtUtc">When the credential was created.</param>
/// <param name="LastUsedAtUtc">When the credential was last used.</param>
public record PasskeyCredentialListItem(Guid Id, string DeviceName, string? Aaguid, DateTime CreatedAtUtc, DateTime? LastUsedAtUtc);

/// <summary>
/// List of passkey credentials for a principal.
/// </summary>
/// <param name="Credentials">The passkey credentials.</param>
public record PasskeyListResponse(List<PasskeyCredentialListItem> Credentials);
