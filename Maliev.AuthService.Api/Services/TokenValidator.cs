using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Maliev.AuthService.Api.Options;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Maliev.AuthService.Api.Services;

/// <summary>
/// Service implementation for validating JWT access tokens.
/// </summary>
public class TokenValidator : ITokenValidator
{
    private readonly JwtOptions _jwtOptions;
    private readonly ECDsa _ecdsaKey;
    private readonly JwtSecurityTokenHandler _tokenHandler;
    private readonly TokenValidationParameters _validationParameters;

    public TokenValidator(IOptions<JwtOptions> jwtOptions)
    {
        _jwtOptions = jwtOptions.Value;
        _tokenHandler = new JwtSecurityTokenHandler();

        // Load ECDSA P-256 private key from PEM format (contains public key)
        _ecdsaKey = ECDsa.Create();
        _ecdsaKey.ImportFromPem(_jwtOptions.SecurityKey);

        var securityKey = new ECDsaSecurityKey(_ecdsaKey);

        _validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = _jwtOptions.Issuer,
            ValidateAudience = true,
            ValidAudience = _jwtOptions.Audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = securityKey,
            ClockSkew = TimeSpan.FromMinutes(5) // Allow 5 minutes clock skew
        };
    }

    public async Task<ClaimsPrincipal?> ValidateTokenAsync(string token)
    {
        try
        {
            var principal = _tokenHandler.ValidateToken(token, _validationParameters, out var validatedToken);
            return await Task.FromResult(principal);
        }
        catch (SecurityTokenException)
        {
            return null; // Token validation failed
        }
        catch (Exception)
        {
            return null; // Unexpected error during validation
        }
    }

    public string? ExtractJti(string token)
    {
        try
        {
            var jwtToken = _tokenHandler.ReadJwtToken(token);
            return jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;
        }
        catch
        {
            return null;
        }
    }
}
