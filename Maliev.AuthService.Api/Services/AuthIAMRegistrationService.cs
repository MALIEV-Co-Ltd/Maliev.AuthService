using Maliev.Aspire.ServiceDefaults.IAM;
using Maliev.AuthService.Api.Authorization;

namespace Maliev.AuthService.Api.Services;

/// <summary>
/// Service that registers Auth Service permissions and roles with the central IAM service on startup.
/// </summary>
public class AuthIAMRegistrationService(
    IConfiguration configuration,
    ILogger<AuthIAMRegistrationService> logger) : IAMRegistrationService(configuration, logger, "auth")
{
    /// <inheritdoc />
    protected override IEnumerable<PermissionRegistration> GetPermissions()
    {
        return AuthPermissions.AllWithDescriptions.Select(p => new PermissionRegistration
        {
            PermissionId = p.Key,
            Description = p.Value
        });
    }

    /// <inheritdoc />
    protected override IEnumerable<RoleRegistration> GetPredefinedRoles()
    {
        // Auth service might not need specific pre-defined roles as it handles authentication,
        // but normally admin roles are defined in IAM service execution.
        // We can return empty if no specific roles are needed for this microservice itself to function
        // that aren't already covered by platform defaults.
        return Enumerable.Empty<RoleRegistration>();
    }
}
