using System.Security.Claims;

namespace Maliev.AuthService.Api.Services;

public interface ITokenValidator
{
    Task<ClaimsPrincipal?> ValidateAccessTokenAsync(string token);
    Task<bool> IsTokenRevokedAsync(string jti);
}
