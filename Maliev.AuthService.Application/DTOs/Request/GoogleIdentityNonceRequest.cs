using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Maliev.AuthService.Application.DTOs.Request;

/// <summary>Requests a one-time nonce for an official Google Identity Services flow.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class GoogleIdentityNonceRequest
{
    /// <summary>Gets or sets the configured MALIEV application selector.</summary>
    [Required(ErrorMessage = "Application is required")]
    [RegularExpression("^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$", ErrorMessage = "Application selector is invalid")]
    public string Application { get; set; } = string.Empty;
}
