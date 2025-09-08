using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Api.Models
{
    public class RateLimitOptions
    {
        public const string SectionName = "RateLimit";
        
        public TokenEndpointLimits TokenEndpoint { get; set; } = new();
        public RefreshEndpointLimits RefreshEndpoint { get; set; } = new();
        public GlobalLimits Global { get; set; } = new();
    }

    public class TokenEndpointLimits
    {
        [Range(1, 1000, ErrorMessage = "Token endpoint permit limit must be between 1 and 1000")]
        public int PermitLimit { get; set; } = 10;
        
        [Range(typeof(TimeSpan), "00:00:01", "01:00:00", ErrorMessage = "Token endpoint window must be between 1 second and 1 hour")]
        public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);
        
        [Range(0, 100, ErrorMessage = "Token endpoint queue limit must be between 0 and 100")]
        public int QueueLimit { get; set; } = 5;
    }

    public class RefreshEndpointLimits
    {
        [Range(1, 1000, ErrorMessage = "Refresh endpoint permit limit must be between 1 and 1000")]
        public int PermitLimit { get; set; } = 20;
        
        [Range(typeof(TimeSpan), "00:00:01", "01:00:00", ErrorMessage = "Refresh endpoint window must be between 1 second and 1 hour")]
        public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);
        
        [Range(0, 100, ErrorMessage = "Refresh endpoint queue limit must be between 0 and 100")]
        public int QueueLimit { get; set; } = 10;
    }

    public class GlobalLimits
    {
        [Range(1, 10000, ErrorMessage = "Global permit limit must be between 1 and 10000")]
        public int PermitLimit { get; set; } = 100;
        
        [Range(typeof(TimeSpan), "00:00:01", "01:00:00", ErrorMessage = "Global window must be between 1 second and 1 hour")]
        public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);
        
        [Range(0, 1000, ErrorMessage = "Global queue limit must be between 0 and 1000")]
        public int QueueLimit { get; set; } = 20;
    }
}