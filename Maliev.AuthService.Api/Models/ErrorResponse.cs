using System.Text.Json.Serialization;

namespace Maliev.AuthService.Api.Models;

/// <summary>
/// Standard error response model for all API errors.
/// </summary>
public class ErrorResponse
{
    /// <summary>
    /// Error code or type (e.g., "invalid_credentials", "token_expired", "token_revoked").
    /// </summary>
    [JsonPropertyName("error")]
    public required string Error { get; set; }

    /// <summary>
    /// Optional human-readable error message with additional details.
    /// </summary>
    [JsonPropertyName("message")]
    public string? Message { get; set; }

    /// <summary>
    /// Optional correlation ID for request tracing.
    /// </summary>
    [JsonPropertyName("correlation_id")]
    public string? CorrelationId { get; set; }
}
