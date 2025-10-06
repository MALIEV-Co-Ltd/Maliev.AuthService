using Maliev.AuthService.Api.Models;

namespace Maliev.AuthService.Api.Services;

/// <summary>
/// Main authentication service interface orchestrating all auth operations.
/// </summary>
public interface IAuthenticationService
{
    /// <summary>
    /// Authenticates user and generates tokens.
    /// </summary>
    Task<LoginResponse?> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Refreshes access token using refresh token (with rotation).
    /// </summary>
    Task<LoginResponse?> RefreshAsync(RefreshRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates access token and returns user identity.
    /// </summary>
    Task<ValidateResponse?> ValidateAsync(ValidateRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes an access token.
    /// </summary>
    Task<bool> RevokeAsync(RevokeRequest request, CancellationToken cancellationToken = default);
}
