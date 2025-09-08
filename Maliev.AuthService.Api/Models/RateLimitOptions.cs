using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Api.Models
{
    public class RateLimitOptions
    {
        public const string SectionName = "RateLimit";

        public RateLimitEndpointOptions TokenEndpoint { get; set; } = new();
        public RateLimitEndpointOptions RefreshEndpoint { get; set; } = new();
        public RateLimitEndpointOptions Global { get; set; } = new();
    }

    public class RateLimitEndpointOptions
    {
        [Range(1, int.MaxValue, ErrorMessage = "PermitLimit must be greater than 0")]
        public int PermitLimit { get; set; } = 100;

        public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);

        [Range(0, int.MaxValue, ErrorMessage = "QueueLimit must be non-negative")]
        public int QueueLimit { get; set; } = 0;
    }
}