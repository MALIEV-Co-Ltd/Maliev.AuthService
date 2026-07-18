namespace Maliev.AuthService.Tests.Workflows;

using System;
using System.IO;
using Xunit;

public sealed class WorkflowContractTests
{
    private static readonly string Root = FindRoot();
    private static readonly string Workflows = Path.Combine(Root, ".github", "workflows");

    [Fact]
    public void PullRequests_UseCredentialFreeValidation()
    {
        var text = Read("pr-validation.yml");
        Assert.Contains("pull_request:", text);
        Assert.DoesNotContain("paths:", text);
        Assert.Contains("contents: read", text);
        Assert.Contains("uses: ./.github/workflows/_validate.yml", text);
        AssertSafe(text);
    }

    [Theory]
    [InlineData("ci-main.yml", "main")]
    [InlineData("ci-develop.yml", "develop")]
    [InlineData("ci-staging.yml", "release/v*")]
    public void BranchAndTagWorkflows_AreValidationOnly(string file, string trigger)
    {
        var text = Read(file);
        Assert.Contains(trigger, text);
        Assert.Contains("uses: ./.github/workflows/_validate.yml", text);
        AssertSafe(text);
    }

    [Fact]
    public void ReusableValidation_IsPinnedAndStable()
    {
        var text = Read("_validate.yml");
        Assert.Contains("workflow_call:", text);
        Assert.Contains("name: validate", text);
        Assert.Contains("persist-credentials: false", text);
        Assert.Contains("actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", text);
        Assert.Contains("actions/setup-dotnet@a98b56852c35b8e3190ac28c8c2271da59106c68", text);
        AssertSafe(text);
    }

    [Fact]
    public void AllWorkflows_ForbidDeploymentAndPrivilegedTriggers()
    {
        foreach (var file in Directory.GetFiles(Workflows, "*.yml"))
        {
            var text = File.ReadAllText(file);
            Assert.DoesNotContain("pull_request_target", text, StringComparison.OrdinalIgnoreCase);
            AssertSafe(text);
        }
    }

    [Fact]
    public void Documentation_StatesTheValidationOnlyReleaseBoundary()
    {
        var readme = File.ReadAllText(Path.Combine(Root, "README.md"));
        Assert.Contains("No workflow in this repository publishes", readme);
        Assert.Contains("Aspire owner review", readme);
    }

    private static void AssertSafe(string text)
    {
        foreach (var value in new[] { "secrets.", "id-token: write", "credentials_json", "google-github-actions/auth", "gcloud auth", "docker push", "maliev-gitops", "GITOPS_PAT", "kustomize edit", "gh pr create" })
        {
            Assert.DoesNotContain(value, text, StringComparison.OrdinalIgnoreCase);
        }
    }

    private static string Read(string file)
    {
        var path = Path.Combine(Workflows, file);
        Assert.True(File.Exists(path), $"Required workflow is missing: {file}");
        return File.ReadAllText(path);
    }

    private static string FindRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Maliev.AuthService.sln"))) return directory.FullName;
        }

        throw new DirectoryNotFoundException("Could not locate AuthService repository root.");
    }
}
