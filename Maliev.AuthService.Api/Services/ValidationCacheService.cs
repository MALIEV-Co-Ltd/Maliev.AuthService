using Maliev.AuthService.Api.Options;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Maliev.AuthService.Api.Services;

/// <summary>
/// Service implementation for caching validation results in memory.
/// </summary>
public class ValidationCacheService : IValidationCacheService
{
    private readonly IMemoryCache _cache;
    private readonly CacheOptions _options;

    public ValidationCacheService(IMemoryCache cache, IOptions<CacheOptions> options)
    {
        _cache = cache;
        _options = options.Value;
    }

    public ExternalValidationResult? Get(string username, string userType)
    {
        var key = GetCacheKey(username, userType);
        return _cache.Get<ExternalValidationResult>(key);
    }

    public void Set(string username, string userType, ExternalValidationResult result)
    {
        var key = GetCacheKey(username, userType);
        var cacheOptions = new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(_options.ValidationCacheTTLSeconds)
        };

        _cache.Set(key, result, cacheOptions);
    }

    public void Remove(string username, string userType)
    {
        var key = GetCacheKey(username, userType);
        _cache.Remove(key);
    }

    private static string GetCacheKey(string username, string userType)
    {
        return $"validation:{userType}:{username}";
    }
}
