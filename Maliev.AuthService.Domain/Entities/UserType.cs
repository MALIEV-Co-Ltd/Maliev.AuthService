namespace Maliev.AuthService.Domain.Entities;

/// <summary>
/// Represents the type of user in the authentication system.
/// </summary>
public enum UserType
{
    /// <summary>
    /// External customer user (validated against Customer Service API)
    /// </summary>
    Customer = 1,

    /// <summary>
    /// Internal employee user (validated against Employee Service API)
    /// </summary>
    Employee = 2
}
