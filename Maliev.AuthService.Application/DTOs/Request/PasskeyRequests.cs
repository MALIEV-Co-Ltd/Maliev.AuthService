using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Application.DTOs.Request;

/// <summary>
/// Request to begin WebAuthn passkey registration.
/// </summary>
public class PasskeyRegistrationBeginRequest
{
    /// <summary>
    /// The principal for whom the passkey is being registered.
    /// </summary>
    [Required]
    public Guid PrincipalId { get; set; }
}

/// <summary>
/// Request to complete WebAuthn passkey registration with the authenticator response.
/// </summary>
public class PasskeyRegistrationCompleteRequest
{
    /// <summary>
    /// The principal who owns this credential.
    /// </summary>
    [Required]
    public Guid PrincipalId { get; set; }

    /// <summary>
    /// WebAuthn credential ID (Base64URL-encoded).
    /// </summary>
    [Required]
    public string CredentialId { get; set; } = string.Empty;

    /// <summary>
    /// PEM-encoded public key from the authenticator.
    /// </summary>
    [Required]
    public string PublicKey { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable device name for the passkey.
    /// </summary>
    [Required]
    public string DeviceName { get; set; } = string.Empty;

    /// <summary>
    /// Authenticator Attestation GUID (optional).
    /// </summary>
    public string? Aaguid { get; set; }
}

/// <summary>
/// Request to begin WebAuthn passkey authentication.
/// </summary>
public class PasskeyAuthBeginRequest
{
    /// <summary>
    /// Optional principal ID for discoverable credential lookup.
    /// </summary>
    public Guid? PrincipalId { get; set; }
}

/// <summary>
/// Request to complete WebAuthn passkey authentication with the authenticator response.
/// </summary>
public class PasskeyAuthCompleteRequest
{
    /// <summary>
    /// WebAuthn credential ID used for authentication.
    /// </summary>
    [Required]
    public string CredentialId { get; set; } = string.Empty;

    /// <summary>
    /// Signature produced by the authenticator.
    /// </summary>
    [Required]
    public string Signature { get; set; } = string.Empty;

    /// <summary>
    /// Authenticator data from the assertion response.
    /// </summary>
    [Required]
    public string AuthenticatorData { get; set; } = string.Empty;

    /// <summary>
    /// Client data JSON from the assertion response.
    /// </summary>
    [Required]
    public string ClientDataJson { get; set; } = string.Empty;

    /// <summary>
    /// Optional user handle for credential discovery.
    /// </summary>
    public string? UserHandle { get; set; }
}
