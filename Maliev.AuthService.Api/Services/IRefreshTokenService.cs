using Maliev.AuthService.Data.Entities;

namespace Maliev.AuthService.Api.Services;

/// <summary>
/// Service interface for refresh token operations (rotation, reuse detection).
/// </summary>
public interface IRefreshTokenService
{
    /// <summary>
    /// Creates a new token family for a user's login session.
    /// </summary>
    Task<Guid> CreateTokenFamilyAsync(string userId, UserType userType, CancellationToken cancellationToken = default);

    /// <summary>
    /// Stores a new refresh token in the database.
    /// </summary>
    Task<RefreshToken> StoreRefreshTokenAsync(string tokenHash, string userId, UserType userType, Guid familyId, DateTime expiresAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates and rotates a refresh token (RFC 9700 compliance).
    /// Returns new refresh token or null if invalid/reused.
    /// </summary>
    Task<RefreshToken?> RotateRefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a refresh token is valid for use.
    /// </summary>
    Task<RefreshToken?> ValidateRefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default);
}
