using Maliev.AuthService.Api.Models;

namespace Maliev.AuthService.Api.Services
{
    public interface IValidationCacheService
    {
        Task<ValidationResult?> GetValidationResultAsync(string username, string userType);

        Task SetValidationResultAsync(string username, string userType, ValidationResult result);

        Task InvalidateUserValidationAsync(string username);

        Task ClearExpiredEntriesAsync();
    }
}