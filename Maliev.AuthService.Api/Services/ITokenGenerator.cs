using Maliev.AuthService.Api.Models.Response;

namespace Maliev.AuthService.Api.Services;

public interface ITokenGenerator
{
    string GenerateAccessToken(Guid userId, string userType, string? email = null, string? name = null);
    string GenerateRefreshToken();
    string HashToken(string token);
    Task<string> GenerateServiceAccessTokenAsync(string clientId, string serviceName);
}
