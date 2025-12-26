using Maliev.AuthService.Data.Entities;

namespace Maliev.AuthService.Api.Services;
/// <summary>
/// Service interface for RefreshToken operations
/// </summary>

public interface IRefreshTokenService
{
    /// <summary>
    /// Creates a new refresh token for a user
    /// </summary>
    /// <param name="userId">The user identifier</param>
    /// <param name="principalId">The principal identifier for IAM</param>
    /// <param name="userType">The type of user</param>
    /// <param name="ipAddress">The IP address of the client</param>
    /// <returns>The refresh token entity and token value</returns>
    Task<(RefreshToken Entity, string TokenValue)> CreateRefreshTokenAsync(Guid userId, Guid principalId, UserType userType, string? ipAddress);

    /// <summary>
    /// Validates a refresh token
    /// </summary>
    /// <param name="token">The refresh token to validate</param>
    /// <returns>The refresh token entity, or null if invalid</returns>
    Task<RefreshToken?> ValidateRefreshTokenAsync(string token);

    /// <summary>
    /// Rotates a refresh token by creating a new one and revoking the old one
    /// </summary>
    /// <param name="oldToken">The old refresh token</param>
    /// <param name="ipAddress">The IP address of the client</param>
    /// <returns>The new refresh token entity and token value</returns>
    Task<(RefreshToken Entity, string TokenValue)> RotateRefreshTokenAsync(RefreshToken oldToken, string? ipAddress);

    /// <summary>
    /// Revokes all tokens in a token family
    /// </summary>
    /// <param name="familyId">The family identifier</param>
    /// <param name="reason">The reason for revocation</param>
    /// <returns>A task representing the asynchronous operation</returns>
    Task RevokeTokenFamilyAsync(Guid familyId, string reason);

    /// <summary>
    /// Checks if token reuse has been detected
    /// </summary>
    /// <param name="tokenHash">The token hash to check</param>
    /// <returns>True if token reuse is detected, otherwise false</returns>
    Task<bool> IsTokenReuseDetectedAsync(string tokenHash);
}
