namespace Maliev.AuthService.Api.Authorization;

/// <summary>
/// AuthService-specific rate-limit policy names.
/// </summary>
public static class AuthRateLimitPolicies
{
    /// <summary>
    /// Fixed-window limiter for machine credential exchange.
    /// </summary>
    public const string ServiceLogin = "service-login";
}
