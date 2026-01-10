using System.Collections.ObjectModel;

namespace Maliev.AuthService.Api.Authorization;

/// <summary>
/// Defines all permissions required by the Auth Service.
/// </summary>
public static class AuthPermissions
{
    /// <summary>
    /// Permission to revoke access and refresh tokens.
    /// </summary>
    public const string RevokeTokens = "auth.tokens.revoke";

    /// <summary>
    /// Permission to view user details and sessions.
    /// </summary>
    public const string ViewUsers = "auth.users.read";

    /// <summary>
    /// Permission to manage user accounts and locks.
    /// </summary>
    public const string ManageUsers = "auth.users.manage";

    /// <summary>
    /// Dictionary of all permissions with their descriptions.
    /// </summary>
    public static readonly ReadOnlyDictionary<string, string> AllWithDescriptions = new(new Dictionary<string, string>
    {
        { RevokeTokens, "Can revoke access and refresh tokens" },
        { ViewUsers, "Can view user details and sessions" },
        { ManageUsers, "Can manage user accounts and locks" }
    });
}
