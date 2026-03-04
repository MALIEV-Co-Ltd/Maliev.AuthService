using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Infrastructure.DbContexts;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Maliev.AuthService.Infrastructure.Services;

/// <summary>
/// Validates JWT access tokens using RSA public key verification and revocation checks.
/// </summary>
public class TokenValidator : ITokenValidator
{
    private readonly IConfiguration _configuration;
    private readonly AuthDbContext _dbContext;
    private readonly ILogger<TokenValidator> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenValidator"/> class.
    /// </summary>
    /// <param name="configuration">The configuration.</param>
    /// <param name="dbContext">The database context.</param>
    /// <param name="logger">The logger instance.</param>
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

            if (publicKeyPem.Trim().StartsWith("-----BEGIN", StringComparison.Ordinal))
            {
                rsa.ImportFromPem(publicKeyPem);
            }
            else
            {
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
                if (decodedString.Trim().StartsWith("-----BEGIN", StringComparison.Ordinal))
                {
                    rsa.ImportFromPem(decodedString);
                }
                else
                {
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

    private Task<ClaimsPrincipal?> ValidateWithRsaAsync(string token, RSA rsa)
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
            var tokenHandler = new JwtSecurityTokenHandler { MapInboundClaims = false };
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
