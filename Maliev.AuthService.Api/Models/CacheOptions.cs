namespace Maliev.AuthService.Api.Models
{
    public class CacheOptions
    {
        public const string SectionName = "Cache";
        
        public ValidationCacheOptions ValidationCache { get; set; } = new();
    }

    public class ValidationCacheOptions
    {
        public bool Enabled { get; set; } = true;
        public TimeSpan ExpirationTime { get; set; } = TimeSpan.FromMinutes(5);
        public TimeSpan SlidingExpirationTime { get; set; } = TimeSpan.FromMinutes(2);
        public int MaxCacheSize { get; set; } = 1000;
    }
}