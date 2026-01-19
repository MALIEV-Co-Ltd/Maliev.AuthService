using Maliev.AuthService.Data.DbContexts;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Maliev.AuthService.Api.Services;
/// <summary>
/// Validator for Token
/// </summary>

public class TokenValidator : ITokenValidator
{
    private readonly IConfiguration _configuration;
    private readonly AuthDbContext _dbContext;
    private readonly ILogger<TokenValidator> _logger;
    /// <summary>
    /// Initializes a new instance of the <see cref="TokenValidator"/> class.
    /// </summary>
    /// <param name="configuration">The configuration</param>
    /// <param name="dbContext">The database context</param>
    /// <param name="logger">The logger instance</param>

    public TokenValidator(IConfiguration configuration, AuthDbContext dbContext, ILogger<TokenValidator> logger)
    {
        _configuration = configuration;
        _dbContext = dbContext;
        _logger = logger;
    }

    /// <inheritdoc/>
    public Task<ClaimsPrincipal?> ValidateAccessTokenAsync(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler { MapInboundClaims = false };
            if (!tokenHandler.CanReadToken(token))
            {
                _logger.LogWarning("Token cannot be read as JWT");
                return Task.FromResult<ClaimsPrincipal?>(null);
            }

            var publicKeyPem = _configuration["Jwt:PublicKey"]
                ?? throw new InvalidOperationException("JWT public key not configured");

            var rsa = RSA.Create();

            // Try direct PEM import first
            if (publicKeyPem.Trim().StartsWith("-----BEGIN"))
            {
                rsa.ImportFromPem(publicKeyPem);
            }
            else
            {
                // Try Base64-encoded PEM or DER
                byte[] keyBytes;
                try
                {
                    keyBytes = Convert.FromBase64String(publicKeyPem);
                }
                catch (FormatException)
                {
                    _logger.LogError("PublicKey is not valid PEM and not valid Base64.");
                    return Task.FromResult<ClaimsPrincipal?>(null);
                }

                var decodedString = Encoding.UTF8.GetString(keyBytes);
                if (decodedString.Trim().StartsWith("-----BEGIN"))
                {
                    rsa.ImportFromPem(decodedString);
                }
                else
                {
                    // Assume raw SPKI DER
                    rsa.ImportSubjectPublicKeyInfo(keyBytes, out _);
                }
            }

            return ValidateWithRsaAsync(token, rsa);
        }
        catch (SecurityTokenException ex)
        {
            _logger.LogWarning(ex, "Token validation failed");
            return Task.FromResult<ClaimsPrincipal?>(null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during token validation");
            return Task.FromResult<ClaimsPrincipal?>(null);
        }
    }

    /// <summary>
    /// Validates a JWT token using the provided RSA instance.
    /// </summary>
    /// <param name="token">The JWT token string.</param>
    /// <param name="rsa">The RSA instance containing the public key.</param>
    /// <returns>A <see cref="ClaimsPrincipal"/> if validation succeeds; otherwise, null.</returns>
    private Task<ClaimsPrincipal?> ValidateWithRsaAsync(string token, System.Security.Cryptography.RSA rsa)
    {
        var issuer = _configuration["Jwt:Issuer"] ?? throw new InvalidOperationException("Jwt:Issuer not found");
        var audience = _configuration["Jwt:Audience"] ?? throw new InvalidOperationException("Jwt:Audience not found");

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = issuer,
            ValidAudience = audience,
            IssuerSigningKey = new RsaSecurityKey(rsa),
            ClockSkew = TimeSpan.FromMinutes(5)
        };

        try
        {
            // Disable claim type mapping to keep original claim names like "sub" instead of full URIs
            var tokenHandler = new JwtSecurityTokenHandler { MapInboundClaims = false };

            // ValidateToken can throw for malformed tokens even if CanReadToken returns true
            // due to structure issues detected during parsing
            var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

            if (validatedToken is not JwtSecurityToken jwtToken ||
                !jwtToken.Header.Alg.Equals(SecurityAlgorithms.RsaSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                _logger.LogWarning("Invalid token algorithm");
                return Task.FromResult<ClaimsPrincipal?>(null);
            }

            return Task.FromResult<ClaimsPrincipal?>(principal);
        }
        catch (ArgumentException ex)
        {
            // Handles "IDX10708: 'base64UrlEncodedString' cannot be null or empty" and similar parsing errors
            _logger.LogWarning(ex, "Token validation failed due to malformed token structure");
            return Task.FromResult<ClaimsPrincipal?>(null);
        }
        catch (SecurityTokenException ex)
        {
            _logger.LogWarning(ex, "Token validation failed");
            return Task.FromResult<ClaimsPrincipal?>(null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during token validation");
            return Task.FromResult<ClaimsPrincipal?>(null);
        }
    }

    /// <inheritdoc/>
    public async Task<bool> IsTokenRevokedAsync(string jti)
    {
        return await _dbContext.RevokedTokens
            .AnyAsync(rt => rt.Jti == jti && rt.ExpiresAt > DateTime.UtcNow);
    }
}
