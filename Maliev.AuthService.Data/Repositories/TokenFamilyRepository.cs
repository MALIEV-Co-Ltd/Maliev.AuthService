using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace Maliev.AuthService.Data.Repositories;

/// <summary>
/// Repository implementation for token family operations.
/// </summary>
public class TokenFamilyRepository : ITokenFamilyRepository
{
    private readonly RefreshTokenDbContext _context;

    public TokenFamilyRepository(RefreshTokenDbContext context)
    {
        _context = context;
    }

    public async Task<TokenFamily?> GetByIdAsync(Guid familyId, CancellationToken cancellationToken = default)
    {
        return await _context.TokenFamilies
            .Include(tf => tf.RefreshTokens)
            .FirstOrDefaultAsync(tf => tf.FamilyId == familyId, cancellationToken);
    }

    public async Task<TokenFamily> CreateAsync(TokenFamily tokenFamily, CancellationToken cancellationToken = default)
    {
        _context.TokenFamilies.Add(tokenFamily);
        await _context.SaveChangesAsync(cancellationToken);
        return tokenFamily;
    }

    public async Task UpdateLastUsedAsync(Guid familyId, CancellationToken cancellationToken = default)
    {
        await _context.TokenFamilies
            .Where(tf => tf.FamilyId == familyId)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(tf => tf.LastUsedAt, DateTime.UtcNow),
                cancellationToken);
    }

    public async Task DeleteExpiredFamiliesAsync(DateTime olderThan, CancellationToken cancellationToken = default)
    {
        await _context.TokenFamilies
            .Where(tf => tf.LastUsedAt < olderThan)
            .ExecuteDeleteAsync(cancellationToken);
    }
}
