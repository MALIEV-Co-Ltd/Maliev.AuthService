using Maliev.AuthService.Application.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Maliev.AuthService.Infrastructure.Services;

/// <summary>
/// Generates JWT access tokens and refresh tokens using RSA asymmetric signing.
/// </summary>
public class TokenGenerator : ITokenGenerator
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<TokenGenerator> _logger;
    private readonly IHostEnvironment _environment;

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenGenerator"/> class.
    /// </summary>
    /// <param name="configuration">The configuration.</param>
    /// <param name="logger">The logger instance.</param>
    /// <param name="environment">The host environment.</param>
    public TokenGenerator(IConfiguration configuration, ILogger<TokenGenerator> logger, IHostEnvironment environment)
    {
        _configuration = configuration;
        _logger = logger;
        _environment = environment;
    }

    private RsaSecurityKey GetRsaSecurityKey()
    {
        var privateKeyPem = _configuration["Jwt:PrivateKey"]
            ?? throw new InvalidOperationException("JWT private key not configured");

        try
        {
            var rsa = RSA.Create();

            if (privateKeyPem.Trim().StartsWith("-----BEGIN", StringComparison.Ordinal))
            {
                rsa.ImportFromPem(privateKeyPem);
            }
            else
            {
                byte[] keyBytes;
                try
                {
                    keyBytes = Convert.FromBase64String(privateKeyPem);
                }
                catch (FormatException)
                {
                    _logger.LogError("PrivateKey is not valid PEM and not valid Base64.");
                    throw new InvalidOperationException("Invalid private key format. Expected PEM or Base64-encoded PEM/DER.");
                }

                var decodedString = Encoding.UTF8.GetString(keyBytes);
                if (decodedString.Trim().StartsWith("-----BEGIN", StringComparison.Ordinal))
                {
                    rsa.ImportFromPem(decodedString);
                }
                else
                {
                    rsa.ImportPkcs8PrivateKey(keyBytes, out _);
                }
            }

            return new RsaSecurityKey(rsa);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to import RSA private key. Ensure key is in valid PEM or PKCS#8 format.");
            throw new InvalidOperationException("Failed to import RSA private key", ex);
        }
    }

    /// <inheritdoc/>
    public string GenerateAccessToken(Guid userId, string userType, string? email = null, string? name = null, IEnumerable<string>? permissions = null, IEnumerable<string>? roles = null)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId.ToString()),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("user_type", userType),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };

        if (!string.IsNullOrEmpty(email))
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, email));
        }

        if (!string.IsNullOrEmpty(name))
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Name, name));
        }

        var rolesList = roles?.ToList() ?? [];

        foreach (var role in rolesList)
        {
            claims.Add(new Claim("roles", role));
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        if (permissions != null)
        {
            foreach (var permission in permissions)
            {
                claims.Add(new Claim("permissions", permission));
            }
        }

        var securityKey = GetRsaSecurityKey();
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

        var issuer = _configuration["Jwt:Issuer"] ?? throw new InvalidOperationException("Jwt:Issuer not found");
        var audience = _configuration["Jwt:Audience"] ?? throw new InvalidOperationException("Jwt:Audience not found");

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(15),
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = credentials
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);

        if (_environment.IsDevelopment())
        {
            var permissionsList = permissions?.ToList() ?? [];
            _logger.LogInformation(
                "Generated JWT for user {UserId} ({UserType}) with {PermissionCount} permissions and {RoleCount} roles",
                userId, userType, permissionsList.Count, rolesList.Count);
        }

        return tokenHandler.WriteToken(token);
    }

    /// <inheritdoc/>
    public string GenerateRefreshToken()
    {
        var randomBytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes);
    }

    /// <inheritdoc/>
    public string HashToken(string token)
    {
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    /// <inheritdoc/>
    public Task<string> GenerateServiceAccessTokenAsync(string clientId, string serviceName, IEnumerable<string>? permissions = null, IEnumerable<string>? roles = null, Guid? principalId = null)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, principalId?.ToString() ?? clientId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("service_name", serviceName),
            new("client_id", clientId),
            new("user_type", "service"),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };

        if (permissions != null)
        {
            foreach (var permission in permissions)
            {
                claims.Add(new Claim("permissions", permission));
            }
        }

        if (roles != null)
        {
            foreach (var role in roles)
            {
                claims.Add(new Claim("roles", role));
            }
        }

        var securityKey = GetRsaSecurityKey();
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

        var issuer = _configuration["Jwt:Issuer"] ?? throw new InvalidOperationException("Jwt:Issuer not found");
        var audience = _configuration["Jwt:Audience"] ?? throw new InvalidOperationException("Jwt:Audience not found");

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(15),
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = credentials
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);

        if (_environment.IsDevelopment())
        {
            _logger.LogInformation(
                "Generated service JWT for {ServiceName} (ClientId: {ClientId})",
                serviceName, clientId);
        }

        return Task.FromResult(tokenHandler.WriteToken(token));
    }
}
