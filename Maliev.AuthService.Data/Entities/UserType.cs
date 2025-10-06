namespace Maliev.AuthService.Data.Entities;

/// <summary>
/// Enumeration representing the type of user in the system.
/// </summary>
public enum UserType
{
    /// <summary>
    /// External customer user
    /// </summary>
    Customer = 0,

    /// <summary>
    /// Internal employee user
    /// </summary>
    Employee = 1
}
