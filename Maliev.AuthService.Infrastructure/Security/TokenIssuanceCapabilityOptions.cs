namespace Maliev.AuthService.Infrastructure.Security;

/// <summary>Configures AuthService's isolated IAM token-issuance capability signer.</summary>
public sealed class TokenIssuanceCapabilityOptions
{
    /// <summary>The configuration section containing Auth's private signing material.</summary>
    public const string ConfigurationSection = "Auth:TokenIssuanceCapability";

    /// <summary>The fixed production capability issuer.</summary>
    public const string Issuer = "https://auth.maliev.com";

    /// <summary>The sole fixed production capability audience.</summary>
    public const string Audience = "https://iam.maliev.com/auth/token-issuance";

    /// <summary>Gets or sets the explicit identifier of the active private key.</summary>
    public string? ActiveKeyId { get; set; }

    /// <summary>Gets or sets the Auth-only RSA private key in PEM format.</summary>
    public string? PrivateKey { get; set; }

    /// <summary>Gets or sets the capability lifetime in seconds.</summary>
    public int LifetimeSeconds { get; set; } = 30;
}
