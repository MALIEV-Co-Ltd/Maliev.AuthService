using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace Maliev.AuthService.Api.Services
{
    public interface IRefreshTokenRepository
    {
        Task<int> CleanExpiredAndRevokedTokensAsync();
        Task<RefreshToken?> GetRefreshTokenByTokenAsync(string token);
        void AddRefreshToken(RefreshToken refreshToken);
        void UpdateRefreshToken(RefreshToken refreshToken);
        Task<int> SaveChangesAsync();
    }
}