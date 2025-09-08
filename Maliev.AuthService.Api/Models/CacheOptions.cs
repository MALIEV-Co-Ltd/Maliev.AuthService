using System.ComponentModel.DataAnnotations;

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
        
        [Range(typeof(TimeSpan), "00:00:30", "01:00:00", ErrorMessage = "Cache expiration time must be between 30 seconds and 1 hour")]
        public TimeSpan ExpirationTime { get; set; } = TimeSpan.FromMinutes(5);
        
        [Range(typeof(TimeSpan), "00:00:30", "00:30:00", ErrorMessage = "Cache sliding expiration time must be between 30 seconds and 30 minutes")]
        public TimeSpan SlidingExpirationTime { get; set; } = TimeSpan.FromMinutes(2);
        
        [Range(10, 10000, ErrorMessage = "Max cache size must be between 10 and 10000 entries")]
        public int MaxCacheSize { get; set; } = 1000;
    }
}