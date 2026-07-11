namespace Maliev.AuthService.Domain.Entities;

/// <summary>
/// Stores one short-lived, caller-bound WebAuthn assertion ceremony.
/// </summary>
public sealed class PasskeyAssertionCeremony
{
    /// <summary>Gets or sets the ceremony record identifier.</summary>
    public Guid Id { get; set; }

    /// <summary>Gets or sets the SHA-256 hash of the browser-visible flow identifier.</summary>
    public string FlowIdHash { get; set; } = string.Empty;

    /// <summary>Gets or sets the SHA-256 hash of the server-generated challenge.</summary>
    public string ChallengeHash { get; set; } = string.Empty;

    /// <summary>Gets or sets the original FIDO2 assertion options JSON.</summary>
    public string AssertionOptionsJson { get; set; } = string.Empty;

    /// <summary>Gets or sets the normalized service caller that created the ceremony.</summary>
    public string ServiceName { get; set; } = string.Empty;

    /// <summary>Gets or sets the normalized MALIEV application audience.</summary>
    public string Application { get; set; } = string.Empty;

    /// <summary>Gets or sets the principal audience permitted to complete the ceremony.</summary>
    public UserType ExpectedUserType { get; set; }

    /// <summary>Gets or sets the UTC creation timestamp.</summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>Gets or sets the UTC expiration timestamp.</summary>
    public DateTime ExpiresAtUtc { get; set; }
}
