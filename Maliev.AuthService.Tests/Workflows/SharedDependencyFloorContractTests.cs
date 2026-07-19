namespace Maliev.AuthService.Tests.Workflows;

using System.Xml.Linq;
using Xunit;

public sealed class SharedDependencyFloorContractTests
{
    [Fact]
    public void SharedDependencyFloors_MatchCurrentServiceDefaults()
    {
        var root = FindRoot();
        var infrastructure = XDocument.Load(Path.Combine(
            root,
            "Maliev.AuthService.Infrastructure",
            "Maliev.AuthService.Infrastructure.csproj"));
        var api = XDocument.Load(Path.Combine(
            root,
            "Maliev.AuthService.Api",
            "Maliev.AuthService.Api.csproj"));
        var tests = XDocument.Load(Path.Combine(
            root,
            "Maliev.AuthService.Tests",
            "Maliev.AuthService.Tests.csproj"));

        AssertVersion(infrastructure, "MassTransit.RabbitMQ", "[8.5.10, 9.0.0)");
        AssertVersion(api, "MassTransit.EntityFrameworkCore", "[8.5.10, 9.0.0)");
        AssertVersion(infrastructure, "Microsoft.EntityFrameworkCore", "10.0.10");
        AssertVersion(infrastructure, "Microsoft.Extensions.Diagnostics.HealthChecks.EntityFrameworkCore", "10.0.10");
        AssertVersion(infrastructure, "Npgsql.EntityFrameworkCore.PostgreSQL", "10.0.3");
        AssertVersion(infrastructure, "Microsoft.IdentityModel.Tokens", "8.19.2");
        AssertVersion(infrastructure, "System.IdentityModel.Tokens.Jwt", "8.19.2");
        AssertVersion(tests, "Microsoft.EntityFrameworkCore", "10.0.10");
        AssertVersion(tests, "Npgsql.EntityFrameworkCore.PostgreSQL", "10.0.3");
    }

    private static void AssertVersion(XDocument project, string packageName, string expectedVersion)
    {
        var reference = Assert.Single(
            project.Descendants("PackageReference"),
            element => element.Attribute("Include")?.Value == packageName);
        Assert.Equal(expectedVersion, reference.Attribute("Version")?.Value);
    }

    private static string FindRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Maliev.AuthService.slnx")))
            {
                return directory.FullName;
            }
        }

        throw new DirectoryNotFoundException("Could not locate AuthService repository root.");
    }
}
