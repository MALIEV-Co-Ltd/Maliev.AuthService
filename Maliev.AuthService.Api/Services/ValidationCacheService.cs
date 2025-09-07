using Maliev.AuthService.Api.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Maliev.AuthService.Api.Services
{
    public class ValidationCacheService : IValidationCacheService
    {
        private readonly IMemoryCache _memoryCache;
        private readonly CacheOptions _cacheOptions;
        private readonly ILogger<ValidationCacheService> _logger;

        public ValidationCacheService(
            IMemoryCache memoryCache,
            IOptions<CacheOptions> cacheOptions,
            ILogger<ValidationCacheService> logger)
        {
            _memoryCache = memoryCache;
            _cacheOptions = cacheOptions.Value;
            _logger = logger;
        }

        public Task<ValidationResult?> GetValidationResultAsync(string username, string userType)
        {
            if (!_cacheOptions.ValidationCache.Enabled)
            {
                return Task.FromResult<ValidationResult?>(null);
            }

            var cacheKey = GetCacheKey(username, userType);
            
            if (_memoryCache.TryGetValue(cacheKey, out ValidationResult? cachedResult))
            {
                _logger.LogDebug("Cache hit for user: {Username}, type: {UserType}", username, userType);
                return Task.FromResult(cachedResult);
            }

            _logger.LogDebug("Cache miss for user: {Username}, type: {UserType}", username, userType);
            return Task.FromResult<ValidationResult?>(null);
        }

        public Task SetValidationResultAsync(string username, string userType, ValidationResult result)
        {
            if (!_cacheOptions.ValidationCache.Enabled)
            {
                return Task.CompletedTask;
            }

            var cacheKey = GetCacheKey(username, userType);
            
            var cacheOptions = new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = _cacheOptions.ValidationCache.ExpirationTime,
                SlidingExpiration = _cacheOptions.ValidationCache.SlidingExpirationTime,
                Size = 1
            };

            _memoryCache.Set(cacheKey, result, cacheOptions);
            _logger.LogDebug("Cached validation result for user: {Username}, type: {UserType}, exists: {Exists}", 
                username, userType, result.Exists);

            return Task.CompletedTask;
        }

        public Task InvalidateUserValidationAsync(string username)
        {
            if (!_cacheOptions.ValidationCache.Enabled)
            {
                return Task.CompletedTask;
            }

            var customerKey = GetCacheKey(username, "Customer");
            var employeeKey = GetCacheKey(username, "Employee");

            _memoryCache.Remove(customerKey);
            _memoryCache.Remove(employeeKey);

            _logger.LogDebug("Invalidated cache for user: {Username}", username);
            return Task.CompletedTask;
        }

        public Task ClearExpiredEntriesAsync()
        {
            // Memory cache handles expiration automatically
            // This method could be used for custom cleanup logic if needed
            _logger.LogDebug("Cache cleanup requested - MemoryCache handles expiration automatically");
            return Task.CompletedTask;
        }

        private static string GetCacheKey(string username, string userType)
        {
            return $"validation_{userType.ToLowerInvariant()}_{username.ToLowerInvariant()}";
        }
    }
}