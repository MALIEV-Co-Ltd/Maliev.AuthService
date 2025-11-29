using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Maliev.AuthService.Api.Services;
/// <summary>
/// Represents a TokenGenerator
/// </summary>

public class TokenGenerator : ITokenGenerator
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<TokenGenerator> _logger;
    /// <summary>
    /// Initializes a new instance of the <see cref="TokenGenerator"/> class.
    /// </summary>
    /// <param name="configuration">The configuration</param>
    /// <param name="logger">The logger instance</param>

    public TokenGenerator(IConfiguration configuration, ILogger<TokenGenerator> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }
    /// <inheritdoc/>
    public string GenerateAccessToken(Guid userId, string userType, string? email = null, string? name = null)
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

        var privateKeyPem = _configuration["Jwt:PrivateKey"]
            ?? throw new InvalidOperationException("JWT private key not configured");

        // Decode Base64-encoded PEM
        var privateKeyBytes = Convert.FromBase64String(privateKeyPem);
        var privateKeyString = Encoding.UTF8.GetString(privateKeyBytes);

        // Import RSA private key from PEM
        var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyString);

        var securityKey = new RsaSecurityKey(rsa);
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
    public Task<string> GenerateServiceAccessTokenAsync(string clientId, string serviceName)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, clientId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("service_name", serviceName),
            new("user_type", "service"),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };

        var privateKeyPem = _configuration["Jwt:PrivateKey"]
            ?? throw new InvalidOperationException("JWT private key not configured");

        // Decode Base64-encoded PEM
        var privateKeyBytes = Convert.FromBase64String(privateKeyPem);
        var privateKeyString = Encoding.UTF8.GetString(privateKeyBytes);

        // Import RSA private key from PEM
        var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyString);

        var securityKey = new RsaSecurityKey(rsa);
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

        var issuer = _configuration["Jwt:Issuer"] ?? throw new InvalidOperationException("Jwt:Issuer not found");
        var audience = _configuration["Jwt:Audience"] ?? throw new InvalidOperationException("Jwt:Audience not found");

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddHours(1),
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = credentials
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);

        return Task.FromResult(tokenHandler.WriteToken(token));
    }
}
