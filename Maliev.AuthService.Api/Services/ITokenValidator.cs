using System.Security.Claims;

namespace Maliev.AuthService.Api.Services;
/// <summary>
/// Interface for TokenValidator
/// </summary>

public interface ITokenValidator
{
    /// <summary>
    /// Validates a JWT access token and returns the claims principal
    /// </summary>
    /// <param name="token">The access token to validate</param>
    /// <returns>The claims principal, or null if validation fails</returns>
    Task<ClaimsPrincipal?> ValidateAccessTokenAsync(string token);

    /// <summary>
    /// Checks if a token has been revoked using its JTI claim
    /// </summary>
    /// <param name="jti">The JWT ID (jti claim)</param>
    /// <returns>True if the token is revoked, otherwise false</returns>
    Task<bool> IsTokenRevokedAsync(string jti);
}
