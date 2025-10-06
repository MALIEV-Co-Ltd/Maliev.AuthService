using System.Security.Claims;

namespace Maliev.AuthService.Api.Services;

/// <summary>
/// Service interface for validating JWT access tokens.
/// </summary>
public interface ITokenValidator
{
    /// <summary>
    /// Validates a JWT access token and extracts claims.
    /// </summary>
    /// <param name="token">JWT token string.</param>
    /// <returns>ClaimsPrincipal if valid, null if invalid.</returns>
    Task<ClaimsPrincipal?> ValidateTokenAsync(string token);

    /// <summary>
    /// Extracts the JTI (JWT ID) claim from a token without full validation.
    /// Used for revocation checking.
    /// </summary>
    /// <param name="token">JWT token string.</param>
    /// <returns>JTI claim value or null if not present.</returns>
    string? ExtractJti(string token);
}
