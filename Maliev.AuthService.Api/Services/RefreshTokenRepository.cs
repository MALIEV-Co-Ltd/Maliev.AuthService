using Maliev.AuthService.Common.Exceptions;
using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Threading;

namespace Maliev.AuthService.Api.Services
{
    public class RefreshTokenRepository : IRefreshTokenRepository
    {
        private readonly RefreshTokenDbContext _dbContext;
        private readonly ILogger<RefreshTokenRepository> _logger;

        public RefreshTokenRepository(RefreshTokenDbContext dbContext, ILogger<RefreshTokenRepository> logger)
        {
            _dbContext = dbContext;
            _logger = logger;
        }

        public async Task<int> CleanExpiredAndRevokedTokensAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // Use ExecuteDeleteAsync for better performance (PostgreSQL, SQL Server, etc.)
                var deletedCount = await _dbContext.RefreshTokens
                    .Where(rt => rt.Expires < DateTime.UtcNow && rt.Revoked != null)
                    .ExecuteDeleteAsync(cancellationToken);
                
                _logger.LogInformation("Cleaned up {DeletedCount} expired and revoked refresh tokens using ExecuteDeleteAsync", deletedCount);
                return deletedCount;
            }
            catch (InvalidOperationException)
            {
                try
                {
                    // Fall back to traditional approach for providers that don't support ExecuteDeleteAsync (like InMemory)
                    var tokensToClean = await _dbContext.RefreshTokens
                        .Where(rt => rt.Expires < DateTime.UtcNow && rt.Revoked != null)
                        .ToListAsync(cancellationToken);

                    if (tokensToClean.Any())
                    {
                        _dbContext.RefreshTokens.RemoveRange(tokensToClean);
                        await _dbContext.SaveChangesAsync(cancellationToken);
                        _logger.LogInformation("Cleaned up {DeletedCount} expired and revoked refresh tokens using traditional approach", tokensToClean.Count);
                        return tokensToClean.Count;
                    }
                    else
                    {
                        _logger.LogInformation("No expired and revoked refresh tokens to clean up");
                        return 0;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to clean expired and revoked tokens using traditional approach");
                    throw new DatabaseOperationException("Failed to clean expired and revoked tokens", ex);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to clean expired and revoked tokens using ExecuteDeleteAsync");
                throw new DatabaseOperationException("Failed to clean expired and revoked tokens", ex);
            }
        }

        public async Task<RefreshToken?> GetRefreshTokenByTokenAsync(string token, CancellationToken cancellationToken = default)
        {
            try
            {
                return await _dbContext.RefreshTokens.SingleOrDefaultAsync(rt => rt.Token == token, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get refresh token by token: {Token}", token);
                throw new DatabaseOperationException($"Failed to get refresh token by token: {token}", ex);
            }
        }

        public void AddRefreshToken(RefreshToken refreshToken)
        {
            _dbContext.RefreshTokens.Add(refreshToken);
        }

        public void UpdateRefreshToken(RefreshToken refreshToken)
        {
            _dbContext.RefreshTokens.Update(refreshToken);
        }

        public async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                return await _dbContext.SaveChangesAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to save changes to database");
                throw new DatabaseOperationException("Failed to save changes to database", ex);
            }
        }
    }
}