using Maliev.AuthService.Api.Models.Request;
using Maliev.AuthService.Api.Models.Response;

namespace Maliev.AuthService.Api.Services;

public interface IAuthenticationService
{
    Task<AuthenticationResult> AuthenticateAsync(LoginRequest request, string? ipAddress);
    Task<TokenResponse?> RefreshTokenAsync(RefreshRequest request, string? ipAddress);
    Task<ValidateResponse> ValidateTokenAsync(ValidateRequest request);
    Task<bool> RevokeTokenAsync(RevokeRequest request);
    Task<bool> LogoutAsync(LogoutRequest request);
    Task<LoginResponse?> AuthenticateServiceAsync(ServiceLoginRequest request, string? ipAddress);
}
