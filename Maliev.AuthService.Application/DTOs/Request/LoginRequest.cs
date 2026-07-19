using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Application.DTOs.Request;

/// <summary>
/// Request model for user login (customer or employee).
/// </summary>
public class LoginRequest
{
    /// <summary>
    /// Username or email address.
    /// </summary>
    [Required]
    [EmailAddress]
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// User password.
    /// </summary>
    [Required]
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// User type: "customer" or "employee".
    /// </summary>
    [Required]
    [RegularExpression("^(customer|employee)$", ErrorMessage = "UserType must be 'customer' or 'employee'")]
    public string UserType { get; set; } = string.Empty;
}
