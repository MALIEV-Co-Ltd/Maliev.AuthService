using System.Security.Claims;

namespace Maliev.AuthService.Api.Services;

/// <summary>
/// Service interface for generating JWT access tokens and refresh tokens.
/// </summary>
public interface ITokenGenerator
{
    /// <summary>
    /// Generates a JWT access token with ES256 signing.
    /// </summary>
    /// <param name="claims">Claims to include in the JWT.</param>
    /// <returns>JWT token string.</returns>
    string GenerateAccessToken(IEnumerable<Claim> claims);

    /// <summary>
    /// Generates a cryptographically secure refresh token.
    /// </summary>
    /// <returns>Base64-encoded refresh token.</returns>
    string GenerateRefreshToken();

    /// <summary>
    /// Computes SHA-256 hash of a refresh token for database storage.
    /// </summary>
    /// <param name="refreshToken">Plaintext refresh token.</param>
    /// <returns>SHA-256 hash as hex string.</returns>
    string HashRefreshToken(string refreshToken);
}
