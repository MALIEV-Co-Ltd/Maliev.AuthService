using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Application.DTOs.Request;

/// <summary>
/// Request model for exchanging a customer Google identity for a Maliev customer JWT.
/// </summary>
public class CustomerGoogleExchangeRequest
{
    /// <summary>
    /// Gets or sets the customer email address from Google.
    /// </summary>
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Must be a valid email address")]
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the customer full name from Google.
    /// </summary>
    public string? FullName { get; set; }

    /// <summary>
    /// Gets or sets Google's OpenID Connect subject claim.
    /// </summary>
    [Required(ErrorMessage = "Google user id is required")]
    public string GoogleUserId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets whether Google reports the email as verified.
    /// </summary>
    public bool EmailVerified { get; set; } = true;

    /// <summary>
    /// Gets or sets the profile image URL from Google.
    /// </summary>
    public string? ProfileImageUrl { get; set; }

    /// <summary>
    /// Gets or sets the customer's preferred language.
    /// </summary>
    public string PreferredLanguage { get; set; } = "th";

    /// <summary>
    /// Gets or sets the customer's preferred timezone.
    /// </summary>
    public string Timezone { get; set; } = "Asia/Bangkok";
}
