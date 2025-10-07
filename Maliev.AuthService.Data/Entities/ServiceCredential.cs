namespace Maliev.AuthService.Data.Entities;

/// <summary>
/// Stores service-to-service authentication credentials for microservice integration.
/// </summary>
public class ServiceCredential
{
    /// <summary>
    /// Unique credential identifier (Primary Key)
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Service client identifier (pattern: service-{environment}-{name})
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// SHA-256 hash of client secret (64 characters hex)
    /// </summary>
    public string ClientSecretHash { get; set; } = string.Empty;

    /// <summary>
    /// Descriptive service name
    /// </summary>
    public string ServiceName { get; set; } = string.Empty;

    /// <summary>
    /// Whether credential is active
    /// </summary>
    public bool IsActive { get; set; }

    /// <summary>
    /// Credential creation timestamp
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Last update timestamp
    /// </summary>
    public DateTime UpdatedAt { get; set; }
}
