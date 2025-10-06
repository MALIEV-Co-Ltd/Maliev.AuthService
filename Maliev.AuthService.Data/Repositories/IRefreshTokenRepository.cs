using Maliev.AuthService.Data.Entities;

namespace Maliev.AuthService.Data.Repositories;

/// <summary>
/// Repository interface for refresh token operations.
/// </summary>
public interface IRefreshTokenRepository
{
    /// <summary>
    /// Finds a refresh token by its SHA-256 hash.
    /// </summary>
    Task<RefreshToken?> GetByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new refresh token in the database.
    /// </summary>
    Task<RefreshToken> CreateAsync(RefreshToken refreshToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks a refresh token as used.
    /// Uses optimistic concurrency control (RowVersion).
    /// </summary>
    Task<bool> MarkAsUsedAsync(Guid id, byte[] version, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all refresh tokens in a token family (reuse detection).
    /// </summary>
    Task RevokeTokenFamilyAsync(Guid familyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes expired refresh tokens older than the specified date.
    /// </summary>
    Task DeleteExpiredTokensAsync(DateTime olderThan, CancellationToken cancellationToken = default);
}
