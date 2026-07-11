using Maliev.AuthService.Domain.Entities;

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

    /// <summary>Gets or sets the maximum outstanding ceremonies for one service/application boundary.</summary>
    public int MaxOutstandingCeremoniesPerApplication { get; set; } = 512;

    /// <summary>Gets or sets trusted application, service, and principal-audience bindings.</summary>
    public Dictionary<string, PasskeyApplicationBinding> Bindings { get; set; } = [];
}

/// <summary>
/// Binds one browser application to its trusted BFF and permitted principal audience.
/// </summary>
public sealed class PasskeyApplicationBinding
{
    /// <summary>Gets or sets the authenticated service name permitted to exchange assertions.</summary>
    public string ServiceName { get; set; } = string.Empty;

    /// <summary>Gets or sets the principal type permitted to authenticate in the application.</summary>
    public UserType PrincipalType { get; set; }
}
