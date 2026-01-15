using Maliev.AuthService.Api.Models.Request;
using Maliev.AuthService.Api.Models.Response;

namespace Maliev.AuthService.Api.Services;
/// <summary>
/// Service interface for Authentication operations
/// </summary>

public interface IAuthenticationService
{
    /// <summary>
    /// Authenticates a user with credentials
    /// </summary>
    /// <param name="request">The login request</param>
    /// <param name="ipAddress">The IP address of the client</param>
    /// <returns>The authentication result</returns>
    Task<AuthenticationResult> AuthenticateAsync(LoginRequest request, string? ipAddress);

    /// <summary>
    /// Refreshes an authentication token
    /// </summary>
    /// <param name="request">The refresh request</param>
    /// <param name="ipAddress">The IP address of the client</param>
    /// <returns>The new token response, or null if refresh failed</returns>
    Task<TokenResponse?> RefreshTokenAsync(RefreshRequest request, string? ipAddress);

    /// <summary>
    /// Validates an access token
    /// </summary>
    /// <param name="request">The validate request</param>
    /// <returns>The validation response</returns>
    Task<ValidateResponse> ValidateTokenAsync(ValidateRequest request);

    /// <summary>
    /// Revokes a refresh token
    /// </summary>
    /// <param name="request">The revoke request</param>
    /// <returns>True if revoked successfully, otherwise false</returns>
    Task<bool> RevokeTokenAsync(RevokeRequest request);

    /// <summary>
    /// Logs out a user by invalidating their refresh token
    /// </summary>
    /// <param name="request">The logout request</param>
    /// <returns>True if logged out successfully, otherwise false</returns>
    Task<bool> LogoutAsync(LogoutRequest request);

    /// <summary>
    /// Authenticates a service using client credentials
    /// </summary>
    /// <param name="request">The service login request</param>
    /// <param name="ipAddress">The IP address of the client</param>
    /// <returns>The login response, or null if authentication failed</returns>
    Task<LoginResponse?> AuthenticateServiceAsync(ServiceLoginRequest request, string? ipAddress);

    /// <summary>
    /// Exchanges a verified Google Workspace identity for a platform JWT
    /// </summary>
    /// <param name="request">The Google exchange request</param>
    /// <param name="ipAddress">The IP address of the client</param>
    /// <returns>The authentication result</returns>
    Task<AuthenticationResult> ExchangeGoogleTokenAsync(GoogleExchangeRequest request, string? ipAddress);
}
