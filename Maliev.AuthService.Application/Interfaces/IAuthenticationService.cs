using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Application.DTOs.Response;

namespace Maliev.AuthService.Application.Interfaces;

/// <summary>
/// Service interface for Authentication operations.
/// </summary>
public interface IAuthenticationService
{
    /// <summary>
    /// Authenticates a user with credentials.
    /// </summary>
    /// <param name="request">The login request.</param>
    /// <param name="ipAddress">The IP address of the client.</param>
    /// <returns>The authentication result.</returns>
    Task<AuthenticationResult> AuthenticateAsync(LoginRequest request, string? ipAddress);

    /// <summary>
    /// Refreshes an authentication token.
    /// </summary>
    /// <param name="request">The refresh request.</param>
    /// <param name="ipAddress">The IP address of the client.</param>
    /// <returns>The new token response, or null if refresh failed.</returns>
    Task<TokenResponse?> RefreshTokenAsync(RefreshRequest request, string? ipAddress);

    /// <summary>
    /// Validates an access token.
    /// </summary>
    /// <param name="request">The validate request.</param>
    /// <returns>The validation response.</returns>
    Task<ValidateResponse> ValidateTokenAsync(ValidateRequest request);

    /// <summary>
    /// Revokes a refresh token.
    /// </summary>
    /// <param name="request">The revoke request.</param>
    /// <returns>True if revoked successfully, otherwise false.</returns>
    Task<bool> RevokeTokenAsync(RevokeRequest request);

    /// <summary>
    /// Logs out a user by invalidating their refresh token.
    /// </summary>
    /// <param name="request">The logout request.</param>
    /// <returns>True if logged out successfully, otherwise false.</returns>
    Task<bool> LogoutAsync(LogoutRequest request);

    /// <summary>
    /// Authenticates a service using client credentials.
    /// </summary>
    /// <param name="request">The service login request.</param>
    /// <param name="ipAddress">The IP address of the client.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The authentication result, including a stable unavailable state.</returns>
    Task<AuthenticationResult> AuthenticateServiceAsync(
        ServiceLoginRequest request,
        string? ipAddress,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Exchanges a verified Google Workspace identity for a platform JWT.
    /// </summary>
    /// <param name="request">The Google exchange request.</param>
    /// <param name="ipAddress">The IP address of the client.</param>
    /// <param name="serviceName">The authenticated service caller bound to the application.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The authentication result.</returns>
    Task<AuthenticationResult> ExchangeGoogleTokenAsync(
        GoogleExchangeRequest request,
        string? ipAddress,
        string serviceName,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Exchanges a verified customer Google identity for a platform JWT.
    /// </summary>
    /// <param name="request">The customer Google exchange request.</param>
    /// <param name="ipAddress">The IP address of the client.</param>
    /// <param name="serviceName">The authenticated service caller bound to the application.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The authentication result.</returns>
    Task<AuthenticationResult> ExchangeCustomerGoogleTokenAsync(
        CustomerGoogleExchangeRequest request,
        string? ipAddress,
        string serviceName,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Starts a customer password reset.
    /// </summary>
    /// <param name="request">The password reset request.</param>
    /// <returns>The reset response.</returns>
    Task<PasswordResetResponse?> RequestPasswordResetAsync(PasswordResetRequest request);

    /// <summary>
    /// Confirms a customer password reset.
    /// </summary>
    /// <param name="request">The password reset confirmation request.</param>
    /// <returns>The reset confirmation response.</returns>
    Task<ConfirmPasswordResetResponse?> ConfirmPasswordResetAsync(ConfirmPasswordResetRequest request);
}
