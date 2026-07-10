using System.Runtime.CompilerServices;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

/// <summary>
/// Source-level checks for customer Google profile image propagation.
/// </summary>
public sealed class CustomerGoogleProfileImageSourceTests
{
    /// <summary>
    /// Verifies customer Google exchange forwards the Google picture URL through the CustomerService session and login response.
    /// </summary>
    [Fact]
    public void CustomerGoogleExchange_ForwardsProfileImageUrlThroughSession()
    {
        var service = ReadRepoFile("Maliev.AuthService.Infrastructure", "Services", "AuthenticationService.cs");

        Assert.Contains("profileImageUrl = identity.ProfileImageUrl", service, StringComparison.Ordinal);
        Assert.Contains("var profileImageUrl = GetString(root, \"profileImageUrl\", \"profile_image_url\", \"ProfileImageUrl\")", service, StringComparison.Ordinal);
        Assert.Contains("ProfileImageUrl = session.ProfileImageUrl", service, StringComparison.Ordinal);
        Assert.Contains("string? ProfileImageUrl", service, StringComparison.Ordinal);
    }

    private static string ReadRepoFile(params string[] pathSegments)
    {
        var root = FindRepoRoot();
        return File.ReadAllText(Path.Combine([root, .. pathSegments]));
    }

    private static string FindRepoRoot([CallerFilePath] string sourceFilePath = "")
    {
        var sourceDirectory = Path.GetDirectoryName(sourceFilePath);
        foreach (var startDirectory in new[] { sourceDirectory, AppContext.BaseDirectory, Directory.GetCurrentDirectory() })
        {
            if (string.IsNullOrWhiteSpace(startDirectory))
            {
                continue;
            }

            var directory = new DirectoryInfo(startDirectory);

            while (directory is not null)
            {
                if (File.Exists(Path.Combine(directory.FullName, "Maliev.AuthService.slnx")))
                {
                    return directory.FullName;
                }

                var siblingCandidate = Path.Combine(directory.FullName, "Maliev.AuthService");
                if (File.Exists(Path.Combine(siblingCandidate, "Maliev.AuthService.slnx")))
                {
                    return siblingCandidate;
                }

                directory = directory.Parent;
            }
        }

        throw new DirectoryNotFoundException("Could not locate Maliev.AuthService repository root.");
    }
}
