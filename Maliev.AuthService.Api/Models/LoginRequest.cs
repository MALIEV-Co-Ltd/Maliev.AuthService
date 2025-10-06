using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Api.Models;

/// <summary>
/// Request model for POST /auth/login endpoint.
/// </summary>
public class LoginRequest
{
    /// <summary>
    /// Username/email for authentication.
    /// </summary>
    [Required(ErrorMessage = "Username is required")]
    [EmailAddress(ErrorMessage = "Username must be a valid email address")]
    public required string Username { get; set; }

    /// <summary>
    /// User password.
    /// </summary>
    [Required(ErrorMessage = "Password is required")]
    [MinLength(8, ErrorMessage = "Password must be at least 8 characters")]
    public required string Password { get; set; }

    /// <summary>
    /// User type: "customer" or "employee".
    /// </summary>
    [Required(ErrorMessage = "User type is required")]
    [RegularExpression("^(customer|employee)$", ErrorMessage = "User type must be 'customer' or 'employee'")]
    public required string UserType { get; set; }
}
