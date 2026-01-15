using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Maliev.AuthService.Data.DbContexts;

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
            var publicKeyPem = _configuration["Jwt:PublicKey"]
                ?? throw new InvalidOperationException("JWT public key not configured");

            string pemContent;
            byte[] publicKeyBytes;

            if (publicKeyPem.StartsWith("-----"))
            {
                pemContent = publicKeyPem;
            }
            else
            {
                // Decode Base64-encoded PEM or DER
                publicKeyBytes = Convert.FromBase64String(publicKeyPem);
                var decodedString = System.Text.Encoding.UTF8.GetString(publicKeyBytes);

                if (decodedString.StartsWith("-----"))
                {
                    pemContent = decodedString;
                }
                else
                {
                    // It's likely raw SubjectPublicKeyInfo (SPKI) DER bytes
                    using var rsaDer = System.Security.Cryptography.RSA.Create();
                    rsaDer.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
                    return ValidateWithRsaAsync(token, rsaDer);
                }
            }

            // Import RSA public key from PEM
            using var rsa = System.Security.Cryptography.RSA.Create();
            rsa.ImportFromPem(pemContent);

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

        // Disable claim type mapping to keep original claim names like "sub" instead of full URIs
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
    /// <inheritdoc/>
    public async Task<bool> IsTokenRevokedAsync(string jti)
    {
        return await _dbContext.RevokedTokens
            .AnyAsync(rt => rt.Jti == jti && rt.ExpiresAt > DateTime.UtcNow);
    }
}
