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

    /// <summary>Permission to provision least-privilege service identities.</summary>
    public const string ProvisionServiceIdentities = "auth.service-identities.provision";

    /// <summary>Permission to read service identity metadata.</summary>
    public const string ReadServiceIdentities = "auth.service-identities.read";

    /// <summary>Permission to rotate service identity secrets.</summary>
    public const string RotateServiceIdentities = "auth.service-identities.rotate";

    /// <summary>Permission to revoke service identities.</summary>
    public const string RevokeServiceIdentities = "auth.service-identities.revoke";

    /// <summary>
    /// Dictionary of all permissions with their descriptions.
    /// </summary>
    public static readonly ReadOnlyDictionary<string, string> AllWithDescriptions = new(new Dictionary<string, string>
    {
        { RevokeTokens, "Can revoke access and refresh tokens" },
        { ViewUsers, "Can view user details and sessions" },
        { ManageUsers, "Can manage user accounts and locks" },
        { ExchangeIdentities, "Can exchange verified external identities for MALIEV sessions" },
        { ProvisionServiceIdentities, "Can provision least-privilege service identities" },
        { ReadServiceIdentities, "Can read service identity metadata" },
        { RotateServiceIdentities, "Can rotate service identity secrets" },
        { RevokeServiceIdentities, "Can revoke service identities" }
    });
}
