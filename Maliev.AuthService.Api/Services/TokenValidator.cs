using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Maliev.AuthService.Data.DbContexts;

namespace Maliev.AuthService.Api.Services;

public class TokenValidator : ITokenValidator
{
    private readonly IConfiguration _configuration;
    private readonly AuthDbContext _dbContext;
    private readonly ILogger<TokenValidator> _logger;

    public TokenValidator(IConfiguration configuration, AuthDbContext dbContext, ILogger<TokenValidator> logger)
    {
        _configuration = configuration;
        _dbContext = dbContext;
        _logger = logger;
    }

    public Task<ClaimsPrincipal?> ValidateAccessTokenAsync(string token)
    {
        try
        {
            var publicKeyPem = _configuration["Jwt:PublicKey"]
                ?? throw new InvalidOperationException("JWT public key not configured");

            // Decode Base64-encoded PEM
            var publicKeyBytes = Convert.FromBase64String(publicKeyPem);
            var publicKeyString = System.Text.Encoding.UTF8.GetString(publicKeyBytes);

            // Import RSA public key from PEM
            var rsa = System.Security.Cryptography.RSA.Create();
            rsa.ImportFromPem(publicKeyString);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidAudience = _configuration["Jwt:Audience"],
                IssuerSigningKey = new RsaSecurityKey(rsa),
                ClockSkew = TimeSpan.Zero
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

    public async Task<bool> IsTokenRevokedAsync(string jti)
    {
        return await _dbContext.RevokedTokens
            .AnyAsync(rt => rt.Jti == jti && rt.ExpiresAt > DateTime.UtcNow);
    }
}
