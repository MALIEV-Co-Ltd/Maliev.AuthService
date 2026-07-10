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
    /// Permission for trusted BFF services to exchange verified external identities for MALIEV sessions.
    /// </summary>
    public const string ExchangeIdentities = "auth.identities.exchange";

    /// <summary>
    /// Dictionary of all permissions with their descriptions.
    /// </summary>
    public static readonly ReadOnlyDictionary<string, string> AllWithDescriptions = new(new Dictionary<string, string>
    {
        { RevokeTokens, "Can revoke access and refresh tokens" },
        { ViewUsers, "Can view user details and sessions" },
        { ManageUsers, "Can manage user accounts and locks" },
        { ExchangeIdentities, "Can exchange verified external identities for MALIEV sessions" }
    });
}
