using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Maliev.AuthService.Api.Options;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Maliev.AuthService.Api.Services;

/// <summary>
/// Service implementation for generating JWT access tokens and refresh tokens.
/// </summary>
public class TokenGenerator : ITokenGenerator
{
    private readonly JwtOptions _jwtOptions;
    private readonly ECDsa _ecdsaKey;
    private readonly JwtSecurityTokenHandler _tokenHandler;

    public TokenGenerator(IOptions<JwtOptions> jwtOptions)
    {
        _jwtOptions = jwtOptions.Value;
        _tokenHandler = new JwtSecurityTokenHandler();

        // Load ECDSA P-256 private key from Base64-encoded raw bytes (32 bytes)
        var privateKeyBytes = Convert.FromBase64String(_jwtOptions.SecurityKey);

        _ecdsaKey = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = privateKeyBytes
        });
    }

    public string GenerateAccessToken(IEnumerable<Claim> claims)
    {
        var securityKey = new ECDsaSecurityKey(_ecdsaKey);
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = _jwtOptions.Issuer,
            Audience = _jwtOptions.Audience,
            Expires = DateTime.UtcNow.AddSeconds(_jwtOptions.AccessTokenLifetimeSeconds),
            IssuedAt = DateTime.UtcNow,
            NotBefore = DateTime.UtcNow,
            SigningCredentials = credentials
        };

        var token = _tokenHandler.CreateToken(tokenDescriptor);
        return _tokenHandler.WriteToken(token);
    }

    public string GenerateRefreshToken()
    {
        // Generate 256-bit cryptographically secure random token
        var randomBytes = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomBytes);
        }
        return Convert.ToBase64String(randomBytes);
    }

    public string HashRefreshToken(string refreshToken)
    {
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(refreshToken));
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }
}
