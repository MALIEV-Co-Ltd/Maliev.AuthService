namespace Maliev.AuthService.Domain.Entities;

/// <summary>
/// Represents a WebAuthn passkey credential bound to a user principal.
/// </summary>
public class PasskeyCredential
{
    /// <summary>
    /// Unique credential identifier (Primary Key).
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// The principal that owns this credential.
    /// </summary>
    public Guid PrincipalId { get; set; }

    /// <summary>
    /// WebAuthn credential ID (Base64URL-encoded).
    /// </summary>
    public string CredentialId { get; set; } = string.Empty;

    /// <summary>
    /// PEM-encoded public key.
    /// </summary>
    public string PublicKey { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable device name.
    /// </summary>
    public string DeviceName { get; set; } = string.Empty;

    /// <summary>
    /// Authenticator Attestation GUID (optional).
    /// </summary>
    public string? Aaguid { get; set; }

    /// <summary>
    /// Signature counter for clone detection.
    /// </summary>
    public int SignCount { get; set; }

    /// <summary>
    /// When the credential was created.
    /// </summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>
    /// When the credential was last used for authentication.
    /// </summary>
    public DateTime? LastUsedAtUtc { get; set; }
}
