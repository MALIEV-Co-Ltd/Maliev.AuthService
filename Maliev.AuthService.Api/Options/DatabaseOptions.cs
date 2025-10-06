namespace Maliev.AuthService.Api.Options;

/// <summary>
/// Database connection configuration.
/// Maps to "Database" section in appsettings.json.
/// Note: Connection string should be loaded from Google Secret Manager in production.
/// </summary>
public class DatabaseOptions
{
    public const string SectionName = "Database";

    /// <summary>
    /// PostgreSQL connection string.
    /// Should come from Google Secret Manager via /mnt/secrets.
    /// </summary>
    public required string ConnectionString { get; set; }

    /// <summary>
    /// Command timeout in seconds. Default: 30.
    /// </summary>
    public int CommandTimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Enable sensitive data logging (for development only). Default: false.
    /// </summary>
    public bool EnableSensitiveDataLogging { get; set; } = false;

    /// <summary>
    /// Maximum retry attempts for transient database failures. Default: 3.
    /// </summary>
    public int MaxRetryCount { get; set; } = 3;

    /// <summary>
    /// Max retry delay for exponential backoff in seconds. Default: 30.
    /// </summary>
    public int MaxRetryDelaySeconds { get; set; } = 30;
}
