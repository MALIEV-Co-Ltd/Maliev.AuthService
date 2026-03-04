using Maliev.AuthService.Application.DTOs.IAM;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public class IAMServiceClientAdditionalTests
{
    [Fact]
    public void PermissionResolutionResponse_SetsPropertiesCorrectly()
    {
        var principalId = Guid.NewGuid();
        var response = new PermissionResolutionResponse
        {
            PrincipalId = principalId,
            Permissions = new List<string> { "read", "write" },
            Roles = new List<string> { "admin" },
            ResolvedAt = DateTime.UtcNow
        };

        Assert.Equal(principalId, response.PrincipalId);
        Assert.Equal(2, response.Permissions.Count);
        Assert.Single(response.Roles);
    }

    [Fact]
    public void PermissionResolutionRequest_SetsPropertiesCorrectly()
    {
        var principalId = Guid.NewGuid().ToString();
        var request = new PermissionResolutionRequest
        {
            PrincipalId = principalId
        };

        Assert.Equal(principalId, request.PrincipalId);
    }
}
