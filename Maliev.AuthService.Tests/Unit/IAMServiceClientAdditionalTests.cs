using Maliev.AuthService.Application.DTOs.IAM;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public class IAMServiceClientAdditionalTests
{
    [Fact]
    public void Program_DefaultIamClient_UsesHttpsFirstServiceDiscovery()
    {
        var programSource = File.ReadAllText(FindProgramSource());

        Assert.Contains("new Uri(\"https+http://IAMService\")", programSource, StringComparison.Ordinal);
        Assert.DoesNotContain("new Uri(\"http://IAMService\")", programSource, StringComparison.Ordinal);
    }

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

    private static string FindProgramSource()
    {
        var current = AppContext.BaseDirectory;
        var directory = new DirectoryInfo(current);

        while (directory != null)
        {
            var candidate = Path.Combine(
                directory.FullName,
                "Maliev.AuthService.Api",
                "Program.cs");

            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException("Unable to locate Maliev.AuthService.Api/Program.cs.");
    }
}
