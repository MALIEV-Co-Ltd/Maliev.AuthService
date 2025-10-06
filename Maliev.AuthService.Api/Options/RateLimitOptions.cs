namespace Maliev.AuthService.Api.Options;

/// <summary>
/// Rate limiting configuration for login attempts.
/// Maps to "RateLimit" section in appsettings.json.
/// </summary>
public class RateLimitOptions
{
    public const string SectionName = "RateLimit";

    /// <summary>
    /// Maximum failed login attempts per window. Default: 5.
    /// </summary>
    public int LoginAttemptLimit { get; set; } = 5;

    /// <summary>
    /// Time window for rate limiting in seconds. Default: 300 (5 minutes).
    /// </summary>
    public int WindowSeconds { get; set; } = 300;

    /// <summary>
    /// Rate limit policy name for middleware.
    /// </summary>
    public string PolicyName => "FixedLoginRateLimit";
}
