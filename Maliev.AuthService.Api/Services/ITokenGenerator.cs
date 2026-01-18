namespace Maliev.AuthService.Api.Services;
/// <summary>
/// Interface for TokenGenerator
/// </summary>

public interface ITokenGenerator
{
    /// <summary>
    /// Generates a JWT access token for a user
    /// </summary>
    /// <param name="userId">The user identifier</param>
    /// <param name="userType">The type of user</param>
    /// <param name="email">The user's email address</param>
    /// <param name="name">The user's name</param>
    /// <param name="permissions">The user's permissions</param>
    /// <param name="roles">The user's roles</param>
    /// <returns>The JWT access token</returns>
    string GenerateAccessToken(Guid userId, string userType, string? email = null, string? name = null, IEnumerable<string>? permissions = null, IEnumerable<string>? roles = null);

    /// <summary>
    /// Generates a cryptographically secure refresh token
    /// </summary>
    /// <returns>The refresh token</returns>
    string GenerateRefreshToken();

    /// <summary>
    /// Hashes a token using SHA-256
    /// </summary>
    /// <param name="token">The token to hash</param>
    /// <returns>The hashed token</returns>
    string HashToken(string token);

    /// <summary>
    /// Generates a JWT access token for a service
    /// </summary>
    /// <param name="clientId">The client identifier</param>
    /// <param name="serviceName">The service name</param>
    /// <param name="permissions">The service's permissions</param>
    /// <param name="roles">The service's roles</param>
    /// <returns>The JWT access token</returns>
    Task<string> GenerateServiceAccessTokenAsync(string clientId, string serviceName, IEnumerable<string>? permissions = null, IEnumerable<string>? roles = null);
}
