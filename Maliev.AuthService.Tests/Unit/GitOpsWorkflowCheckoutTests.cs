using Xunit;

namespace Maliev.AuthService.Tests.Unit;

/// <summary>
/// Verifies branch validation cannot mutate the GitOps repository.
/// </summary>
public sealed class GitOpsWorkflowCheckoutTests
{
    /// <summary>
    /// Branch workflows must delegate to the reusable validation workflow without deployment credentials.
    /// </summary>
    /// <param name="workflowFile">The branch validation workflow file name.</param>
    [Theory]
    [InlineData("ci-develop.yml")]
    [InlineData("ci-staging.yml")]
    [InlineData("ci-main.yml")]
    public void BranchWorkflow_IsValidationOnly(string workflowFile)
    {
        var source = ReadRepositoryFile(".github", "workflows", workflowFile);
        const string leastPrivilegePermissions = "permissions:\n  contents: read";

        Assert.Contains(leastPrivilegePermissions, source, StringComparison.Ordinal);
        Assert.Contains("uses: ./.github/workflows/_validate.yml", source, StringComparison.Ordinal);
        Assert.DoesNotContain("MALIEV-Co-Ltd/maliev-gitops", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("GITOPS_PAT", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("kustomize", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("docker push", source, StringComparison.OrdinalIgnoreCase);
    }

    private static string ReadRepositoryFile(params string[] segments)
    {
        var path = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..",
            "..",
            "..",
            "..",
            Path.Combine(segments)));
        Assert.True(File.Exists(path), $"Could not find workflow file: {path}");
        return File.ReadAllText(path);
    }
}
