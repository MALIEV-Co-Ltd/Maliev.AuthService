using Maliev.AuthService.Data.Entities;

namespace Maliev.AuthService.Data.Repositories;

/// <summary>
/// Repository interface for token family operations.
/// </summary>
public interface ITokenFamilyRepository
{
    /// <summary>
    /// Gets a token family by its ID.
    /// </summary>
    Task<TokenFamily?> GetByIdAsync(Guid familyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new token family.
    /// </summary>
    Task<TokenFamily> CreateAsync(TokenFamily tokenFamily, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates the last used timestamp for a token family.
    /// </summary>
    Task UpdateLastUsedAsync(Guid familyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes token families older than the specified date.
    /// </summary>
    Task DeleteExpiredFamiliesAsync(DateTime olderThan, CancellationToken cancellationToken = default);
}
