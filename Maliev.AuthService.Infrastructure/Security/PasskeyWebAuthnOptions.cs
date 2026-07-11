namespace Maliev.AuthService.Infrastructure.Security;

/// <summary>
/// Configures the MALIEV WebAuthn relying-party policy.
/// </summary>
public sealed class PasskeyWebAuthnOptions
{
    /// <summary>Gets or sets whether passkey authentication is available.</summary>
    public bool Enabled { get; set; }

    /// <summary>Gets or sets the WebAuthn relying-party identifier.</summary>
    public string RpId { get; set; } = string.Empty;

    /// <summary>Gets or sets the human-readable relying-party name.</summary>
    public string RpName { get; set; } = "MALIEV";

    /// <summary>Gets or sets the exact browser origins allowed to authenticate.</summary>
    public IReadOnlyList<string> AllowedOrigins { get; set; } = [];

    /// <summary>Gets or sets the browser ceremony timeout in milliseconds.</summary>
    public int TimeoutMilliseconds { get; set; } = 300_000;

    /// <summary>Gets or sets the number of random bytes in each challenge.</summary>
    public int ChallengeSize { get; set; } = 32;

    /// <summary>Gets or sets the server-side ceremony lifetime in minutes.</summary>
    public int CeremonyLifetimeMinutes { get; set; } = 5;
}
