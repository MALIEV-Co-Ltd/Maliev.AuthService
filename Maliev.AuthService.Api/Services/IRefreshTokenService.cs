using Maliev.AuthService.Data.Entities;

namespace Maliev.AuthService.Api.Services;

public interface IRefreshTokenService
{
    Task<(RefreshToken Entity, string TokenValue)> CreateRefreshTokenAsync(Guid userId, UserType userType, string? ipAddress);
    Task<RefreshToken?> ValidateRefreshTokenAsync(string token);
    Task<(RefreshToken Entity, string TokenValue)> RotateRefreshTokenAsync(RefreshToken oldToken, string? ipAddress);
    Task RevokeTokenFamilyAsync(Guid familyId, string reason);
    Task<bool> IsTokenReuseDetectedAsync(string tokenHash);
}
