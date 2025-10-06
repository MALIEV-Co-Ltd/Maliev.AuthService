namespace Maliev.AuthService.Api.Options;

/// <summary>
/// Circuit breaker configuration for external service resilience.
/// Maps to "CircuitBreaker" section in appsettings.json.
/// </summary>
public class CircuitBreakerOptions
{
    public const string SectionName = "CircuitBreaker";

    /// <summary>
    /// Number of consecutive failures before circuit opens. Default: 5.
    /// </summary>
    public int FailureThreshold { get; set; } = 5;

    /// <summary>
    /// Duration circuit stays open before half-open in seconds. Default: 30.
    /// </summary>
    public int DurationOfBreakSeconds { get; set; } = 30;

    /// <summary>
    /// Sampling duration for failure tracking in seconds. Default: 60.
    /// </summary>
    public int SamplingDurationSeconds { get; set; } = 60;

    /// <summary>
    /// Minimum throughput (requests) before circuit breaker activates. Default: 10.
    /// </summary>
    public int MinimumThroughput { get; set; } = 10;
}
