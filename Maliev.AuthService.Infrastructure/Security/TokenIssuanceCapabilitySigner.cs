using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Maliev.AuthService.Infrastructure.Security;

/// <summary>Creates exact, short-lived capabilities for IAM permission resolution.</summary>
public interface ITokenIssuanceCapabilitySigner
{
    /// <summary>Creates a capability bound to one target IAM principal.</summary>
    /// <param name="targetPrincipalId">The exact target principal.</param>
    /// <returns>A signed compact JWT.</returns>
    string CreateCapability(Guid targetPrincipalId);
}

/// <summary>Signs isolated IAM permission-resolution capabilities with Auth-only key material.</summary>
public sealed class TokenIssuanceCapabilitySigner : ITokenIssuanceCapabilitySigner
{
    private const int MaximumLifetimeSeconds = 60;
    private readonly TokenIssuanceCapabilityOptions _options;
    private readonly TimeProvider _timeProvider;

    /// <summary>Initializes a capability signer.</summary>
    /// <param name="options">The isolated signing options.</param>
    /// <param name="timeProvider">The source of issuance time.</param>
    public TokenIssuanceCapabilitySigner(
        IOptions<TokenIssuanceCapabilityOptions> options,
        TimeProvider timeProvider)
    {
        _options = options.Value;
        _timeProvider = timeProvider;
    }

    /// <inheritdoc/>
    public string CreateCapability(Guid targetPrincipalId)
    {
        ArgumentOutOfRangeException.ThrowIfEqual(targetPrincipalId, Guid.Empty);

        if (string.IsNullOrWhiteSpace(_options.ActiveKeyId) ||
            !string.Equals(_options.ActiveKeyId, _options.ActiveKeyId.Trim(), StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(_options.PrivateKey) ||
            _options.LifetimeSeconds is < 1 or > MaximumLifetimeSeconds)
        {
            throw new InvalidOperationException("Token-issuance capability signing is not configured correctly.");
        }

        using var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(_options.PrivateKey);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidOperationException("Token-issuance capability signing key is invalid.", exception);
        }
        catch (CryptographicException exception)
        {
            throw new InvalidOperationException("Token-issuance capability signing key is invalid.", exception);
        }

        var nowSeconds = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        var now = DateTimeOffset.FromUnixTimeSeconds(nowSeconds);
        var claims = new Claim[]
        {
            new(JwtRegisteredClaimNames.Sub, "urn:maliev:service:auth"),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("D")),
            new(JwtRegisteredClaimNames.Iat, nowSeconds.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
            new("service_name", "AuthService"),
            new("client_id", "auth-service"),
            new("user_type", "service"),
            new("purpose", "iam.permission-resolution"),
            new("target_principal_id", targetPrincipalId.ToString("D")),
            new("permissions", "iam.auth.resolve-permissions")
        };
        var signingKey = new RsaSecurityKey(rsa.ExportParameters(includePrivateParameters: true))
        {
            KeyId = _options.ActiveKeyId
        };
        var token = new JwtSecurityToken(
            TokenIssuanceCapabilityOptions.Issuer,
            TokenIssuanceCapabilityOptions.Audience,
            claims,
            now.UtcDateTime,
            now.AddSeconds(_options.LifetimeSeconds).UtcDateTime,
            new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256));

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
