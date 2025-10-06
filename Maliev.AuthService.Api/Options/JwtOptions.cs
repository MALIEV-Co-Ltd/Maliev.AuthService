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
    /// ECDSA P-256 private key for ES256 signing (PEM format).
    /// Should be loaded from Google Secret Manager in production.
    /// </summary>
    public required string SigningKey { get; set; }

    /// <summary>
    /// Access token lifetime in seconds. Default: 900 (15 minutes).
    /// </summary>
    public int AccessTokenLifetimeSeconds { get; set; } = 900;

    /// <summary>
    /// Refresh token lifetime in seconds. Default: 2592000 (30 days).
    /// </summary>
    public int RefreshTokenLifetimeSeconds { get; set; } = 2592000;

    /// <summary>
    /// Algorithm for signing JWTs. Fixed to ES256 (ECDSA P-256) per spec.
    /// </summary>
    public string Algorithm => "ES256";
}
