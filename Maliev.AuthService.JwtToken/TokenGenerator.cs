using Maliev.AuthService.JwtToken.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

// Assuming RefreshToken model is defined in Maliev.AuthService.Api.Models
// We will pass it as a parameter to avoid direct dependency
// public class RefreshToken { ... }

namespace Maliev.AuthService.JwtToken
{
    /// <summary>
    /// TokenGenerator.
    /// </summary>
    public class TokenGenerator : ITokenGenerator
    {
        private readonly JwtOptions _jwtOptions;
        private readonly ILogger<TokenGenerator> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenGenerator"/> class.
        /// </summary>
        public TokenGenerator(IOptions<JwtOptions> jwtOptions, ILogger<TokenGenerator> logger)
        {
            _jwtOptions = jwtOptions.Value;
            _logger = logger;
        }

        /// <summary>
        /// Generates the JWT token.
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        /// <param name="roles">List of roles for the user.</param>
        /// <param name="expiresInMinutes">The expiration time in minutes for the token. If null, a default will be used.</param>
        /// <returns>
        ///   <see cref="string" />.
        /// </returns>
        public string GenerateJwtToken(string userName, List<string> roles, int? expiresInMinutes = null)
        {
            _logger.LogInformation("Generating JWT token for user: {UserName}, roles: {Roles}", userName, string.Join(", ", roles));

            var claimData = new List<Claim>
            {
                new Claim(ClaimTypes.Name, userName),
                new Claim(ClaimTypes.Email, userName),
            };

            // Add roles as claims
            foreach (var role in roles)
            {
                claimData.Add(new Claim(ClaimTypes.Role, role));
            }

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.SecurityKey));
            SigningCredentials credential = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

            var expires = expiresInMinutes.HasValue ? DateTime.UtcNow.AddMinutes(expiresInMinutes.Value) : DateTime.UtcNow.AddMinutes(30);

            JwtSecurityToken token = new JwtSecurityToken(
                issuer: _jwtOptions.Issuer,
                audience: _jwtOptions.Audience,
                expires: expires,
                claims: claimData,
                signingCredentials: credential);

            var tokenString = tokenHandler.WriteToken(token);
            _logger.LogInformation("Generated JWT token: {Token}", TruncateToken(tokenString));
            return tokenString;
        }

        /// <summary>
        /// Refreshes the JWT token.
        /// </summary>
        /// <param name="token">The expired JWT token.</param>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>A new JWT token and refresh token.</returns>
        public (string accessToken, string refreshToken) RefreshToken(string token, string refreshToken)
        {
            _logger.LogInformation("Refreshing token. Expired Token: {ExpiredToken}, Refresh Token: {RefreshToken}", TruncateToken(token), TruncateToken(refreshToken));

            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = tokenHandler.ReadToken(token) as JwtSecurityToken;
            var username = jwtSecurityToken.Claims.First(claim => claim.Type == ClaimTypes.Name).Value;
            var roles = jwtSecurityToken.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value).ToList();


            _logger.LogInformation("Extracted username: {Username}, roles: {Roles} from expired token.", username, string.Join(", ", roles));

            // This method will not interact with the database directly.
            // The AuthenticationController will handle the database operations.
            // For now, we will just generate new tokens.
            // The actual validation of the refresh token (e.g., checking if it's active, not revoked)
            // will be done in the AuthenticationController.

            var newAccessToken = GenerateJwtToken(username, roles);
            var newRefreshToken = GenerateRefreshTokenString(); // Generate just the string

            _logger.LogInformation("Generated new access token and refresh token.");

            return (newAccessToken, newRefreshToken);
        }

        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            _logger.LogInformation("Getting principal from expired token: {Token}", TruncateToken(token));

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidAudience = _jwtOptions.Audience,
                ValidateIssuer = true,
                ValidIssuer = _jwtOptions.Issuer,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.SecurityKey)),
                ValidateLifetime = false, // We don't care if the token is expired
                ClockSkew = TimeSpan.FromMinutes(5)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256Signature, StringComparison.InvariantCultureIgnoreCase))
            {
                _logger.LogWarning("Invalid token. Token is null or algorithm is not HmacSha256.");
                throw new SecurityTokenException("Invalid token");
            }
            _logger.LogInformation("Successfully validated JWT token.");

            return principal;
        }

        /// <summary>
        /// Generates a new refresh token string.
        /// </summary>
        /// <returns>A new refresh token string.</returns>
        public string GenerateRefreshTokenString()
        {
            var randomBytes = new byte[64];
            RandomNumberGenerator.Fill(randomBytes);
            return Convert.ToBase64String(randomBytes);
        }

        private string TruncateToken(string token)
        {
            if (string.IsNullOrEmpty(token) || token.Length <= 8)
            {
                return token;
            }
            return token.Substring(0, 8) + "...";
        }
    }
}