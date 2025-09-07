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
        public int PermitLimit { get; set; } = 10;
        public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);
        public int QueueLimit { get; set; } = 5;
    }

    public class RefreshEndpointLimits
    {
        public int PermitLimit { get; set; } = 20;
        public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);
        public int QueueLimit { get; set; } = 10;
    }

    public class GlobalLimits
    {
        public int PermitLimit { get; set; } = 100;
        public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);
        public int QueueLimit { get; set; } = 20;
    }
}