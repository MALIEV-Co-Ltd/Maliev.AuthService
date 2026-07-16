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
    public void Program_TokenIssuanceClient_IsBoundedAndHasNoLegacyAuthenticationOrRetryHandler()
    {
        var programSource = File.ReadAllText(FindProgramSource());
        var start = programSource.IndexOf(
            "AddHttpClient<ITokenIssuancePermissionClient, TokenIssuancePermissionClient>",
            StringComparison.Ordinal);
        var end = start >= 0
            ? programSource.IndexOf(
                "// Dedicated human-authorized client",
                start,
                StringComparison.Ordinal)
            : -1;

        Assert.True(start >= 0);
        Assert.True(end > start);
        var registration = programSource[start..end];
        Assert.Contains("client.Timeout = TimeSpan.FromSeconds(10)", registration, StringComparison.Ordinal);
        Assert.Contains(".AddServiceDiscovery()", registration, StringComparison.Ordinal);
        Assert.DoesNotContain(".AddHttpMessageHandler", registration, StringComparison.Ordinal);
        Assert.DoesNotContain(".AddPolicyHandler", registration, StringComparison.Ordinal);
        Assert.DoesNotContain(".AddResilienceHandler", registration, StringComparison.Ordinal);
        Assert.DoesNotContain("ServiceAccountAuthenticationHandler", registration, StringComparison.Ordinal);
        Assert.DoesNotContain("IServiceAccountTokenProvider", registration, StringComparison.Ordinal);
        Assert.DoesNotContain("AuthServiceTokenProvider", registration, StringComparison.Ordinal);
        Assert.DoesNotContain("AddStandardResilienceHandler", registration, StringComparison.Ordinal);
        Assert.DoesNotContain("AddTransientHttpErrorPolicy", registration, StringComparison.Ordinal);

        var optionsStart = programSource.IndexOf(
            "AddOptions<TokenIssuanceCapabilityOptions>",
            StringComparison.Ordinal);
        Assert.True(optionsStart >= 0);
        var optionsRegistration = programSource[optionsStart..start];
        Assert.DoesNotContain("ValidateOnStart", optionsRegistration, StringComparison.Ordinal);
        Assert.DoesNotContain("Jwt", optionsRegistration, StringComparison.Ordinal);
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
