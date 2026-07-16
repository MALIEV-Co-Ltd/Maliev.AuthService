using Xunit;

namespace Maliev.AuthService.Tests.Unit;

/// <summary>
/// Verifies cross-repository GitOps checkouts are deterministic and do not depend on default-branch discovery.
/// </summary>
public sealed class GitOpsWorkflowCheckoutTests
{
    /// <summary>
    /// Every deployment workflow must explicitly check out the GitOps main branch.
    /// </summary>
    /// <param name="workflowFile">The deployment workflow file name.</param>
    [Theory]
    [InlineData("ci-develop.yml")]
    [InlineData("ci-staging.yml")]
    [InlineData("ci-main.yml")]
    public void GitOpsCheckout_PinsMainBranch(string workflowFile)
    {
        var source = ReadRepositoryFile(".github", "workflows", workflowFile);
        const string repositoryLine = "repository: MALIEV-Co-Ltd/maliev-gitops";
        var repositoryIndex = source.IndexOf(repositoryLine, StringComparison.Ordinal);

        Assert.True(repositoryIndex >= 0, $"{workflowFile} must check out the GitOps repository.");

        var checkoutBlockEnd = source.IndexOf("\n      - name:", repositoryIndex, StringComparison.Ordinal);
        var checkoutBlock = checkoutBlockEnd >= 0
            ? source[repositoryIndex..checkoutBlockEnd]
            : source[repositoryIndex..];

        Assert.Contains("ref: main", checkoutBlock, StringComparison.Ordinal);
        Assert.Contains("path: maliev-gitops", checkoutBlock, StringComparison.Ordinal);
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
