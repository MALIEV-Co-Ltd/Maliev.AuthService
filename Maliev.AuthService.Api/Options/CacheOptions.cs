namespace Maliev.AuthService.Api.Options;

/// <summary>
/// In-memory cache configuration for validation caching.
/// Maps to "Cache" section in appsettings.json.
/// </summary>
public class CacheOptions
{
    public const string SectionName = "Cache";

    /// <summary>
    /// Default cache TTL in seconds. Default: 300 (5 minutes).
    /// </summary>
    public int DefaultTTLSeconds { get; set; } = 300;

    /// <summary>
    /// Validation result cache TTL in seconds. Default: 600 (10 minutes).
    /// </summary>
    public int ValidationCacheTTLSeconds { get; set; } = 600;

    /// <summary>
    /// Maximum cache entries. Default: 10000.
    /// Note: No SizeLimit on MemoryCache to avoid requiring Size on all entries.
    /// </summary>
    public int MaxEntries { get; set; } = 10000;

    /// <summary>
    /// Enable cache compression for large entries. Default: false.
    /// </summary>
    public bool EnableCompression { get; set; } = false;
}
