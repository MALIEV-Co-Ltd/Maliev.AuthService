namespace Maliev.AuthService.Api.Options;

/// <summary>
/// JWT configuration options for access and refresh tokens.
/// Maps to "Jwt" section in appsettings.json.
/// </summary>
public class JwtOptions
{
    public const string SectionName = "Jwt";

    /// <summary>
    /// JWT issuer claim (iss). Typically the authentication service URL.
    /// </summary>
    public required string Issuer { get; set; }

    /// <summary>
    /// JWT audience claim (aud). Services that will validate the token.
    /// </summary>
    public required string Audience { get; set; }

    /// <summary>
    /// ECDSA P-256 private key for ES256 signing (Base64-encoded 32-byte raw scalar).
    /// Should be loaded from Google Secret Manager in production (Jwt__SecurityKey).
    /// Example format: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" (32 bytes)
    /// </summary>
    public required string SecurityKey { get; set; }

    /// <summary>
    /// Access token lifetime in seconds. Default: 900 (15 minutes).
    /// </summary>
    public int AccessTokenLifetimeSeconds { get; set; } = 900;

    /// <summary>
    /// Refresh token lifetime in seconds. Default: 2592000 (30 days).
    /// </summary>
    public int RefreshTokenLifetimeSeconds { get; set; } = 2592000;

    /// <summary>
    /// Algorithm for signing JWTs. Fixed to ES256 (ECDSA P-256).
    /// </summary>
    public string Algorithm => "ES256";
}
