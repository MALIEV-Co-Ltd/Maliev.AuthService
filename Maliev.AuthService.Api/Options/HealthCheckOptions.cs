namespace Maliev.AuthService.Api.Options;

/// <summary>
/// Health check endpoint configuration.
/// Maps to "HealthChecks" section in appsettings.json.
/// </summary>
public class HealthCheckOptions
{
    public const string SectionName = "HealthChecks";

    /// <summary>
    /// Liveness endpoint path. Default: "/auth/liveness".
    /// </summary>
    public string LivenessPath { get; set; } = "/auth/liveness";

    /// <summary>
    /// Readiness endpoint path. Default: "/auth/readiness".
    /// </summary>
    public string ReadinessPath { get; set; } = "/auth/readiness";

    /// <summary>
    /// Enable detailed health check responses. Default: false (production).
    /// </summary>
    public bool EnableDetailedErrors { get; set; } = false;

    /// <summary>
    /// Timeout for health checks in seconds. Default: 5.
    /// </summary>
    public int TimeoutSeconds { get; set; } = 5;
}
