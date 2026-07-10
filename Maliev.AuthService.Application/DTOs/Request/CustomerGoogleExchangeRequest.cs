using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Maliev.AuthService.Application.DTOs.Request;

/// <summary>
/// Request model for exchanging a customer Google identity for a Maliev customer JWT.
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public class CustomerGoogleExchangeRequest
{
    /// <summary>
    /// Gets or sets the raw Google Identity Services ID token.
    /// </summary>
    [Required(ErrorMessage = "Google credential is required")]
    [StringLength(8192, MinimumLength = 1, ErrorMessage = "Google credential is invalid")]
    public string Credential { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the configured MALIEV application selector.
    /// </summary>
    [Required(ErrorMessage = "Application is required")]
    [RegularExpression("^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$", ErrorMessage = "Application selector is invalid")]
    public string Application { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the customer's preferred language.
    /// </summary>
    [StringLength(12, MinimumLength = 2)]
    public string PreferredLanguage { get; set; } = "th";

    /// <summary>
    /// Gets or sets the customer's preferred timezone.
    /// </summary>
    [StringLength(100, MinimumLength = 1)]
    public string Timezone { get; set; } = "Asia/Bangkok";
}
