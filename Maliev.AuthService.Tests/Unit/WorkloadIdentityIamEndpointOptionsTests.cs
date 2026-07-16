using Maliev.AuthService.Infrastructure.HttpClients;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public sealed class WorkloadIdentityIamEndpointOptionsTests
{
    [Theory]
    [InlineData("Development", "https+http://IAMService")]
    [InlineData("Testing", "https+http://IAMService")]
    [InlineData("Production", "https://IAMService")]
    [InlineData("Staging", "https://IAMService")]
    public void Resolve_NoConfiguredBaseUrl_UsesEnvironmentSafeDefault(
        string environmentName,
        string expected)
    {
        var resolver = new WorkloadIdentityIamEndpointResolver(new TestEnvironment(environmentName));

        var result = resolver.Resolve(new WorkloadIdentityIamEndpointOptions());

        Assert.Equal(expected, result.OriginalString);
    }

    [Theory]
    [InlineData("Production", "https://iam.internal")]
    [InlineData("Development", "https://iam.internal:7443")]
    [InlineData("Development", "http://localhost:5100")]
    [InlineData("Testing", "http://127.0.0.1:5100")]
    [InlineData("Testing", "http://[::1]:5100")]
    public void Resolve_CanonicalTrustedOrigin_ReturnsConfiguredOrigin(
        string environmentName,
        string baseUrl)
    {
        var resolver = new WorkloadIdentityIamEndpointResolver(new TestEnvironment(environmentName));

        var result = resolver.Resolve(new WorkloadIdentityIamEndpointOptions { BaseUrl = baseUrl });

        Assert.Equal(baseUrl, result.OriginalString);
    }

    [Theory]
    [InlineData("Production", "http://localhost:5100")]
    [InlineData("Development", "http://iam.internal")]
    [InlineData("Development", " https://iam.internal")]
    [InlineData("Development", "https://iam.internal ")]
    [InlineData("Development", "HTTPS://iam.internal")]
    [InlineData("Development", "https://IAM.INTERNAL")]
    [InlineData("Development", "https://user@iam.internal")]
    [InlineData("Development", "https://iam.internal/")]
    [InlineData("Development", "https://iam.internal/path")]
    [InlineData("Development", "https://iam.internal?query=1")]
    [InlineData("Development", "https://iam.internal#fragment")]
    [InlineData("Development", "https+http://IAMService")]
    public void Resolve_UntrustedOrNoncanonicalOrigin_ThrowsOptionsValidation(
        string environmentName,
        string baseUrl)
    {
        var resolver = new WorkloadIdentityIamEndpointResolver(new TestEnvironment(environmentName));

        Assert.Throws<OptionsValidationException>(() =>
            resolver.Resolve(new WorkloadIdentityIamEndpointOptions { BaseUrl = baseUrl }));
    }

    [Fact]
    public void AddWorkloadIdentityIamEndpoint_UnsafeConfiguredOrigin_FailsOptionsResolution()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["Services:IAMService:BaseUrl"] = "http://iam.internal"
            }).Build();
        var services = new ServiceCollection();

        services.AddWorkloadIdentityIamEndpoint(
            configuration.GetSection("Services:IAMService"),
            new TestEnvironment(Environments.Production));
        using var provider = services.BuildServiceProvider();

        Assert.Throws<OptionsValidationException>(() =>
            provider.GetRequiredService<IOptions<WorkloadIdentityIamEndpointOptions>>().Value);
    }

    [Fact]
    public async Task AddWorkloadIdentityIamEndpoint_UnsafeProductionOrigin_FailsHostStartup()
    {
        using var host = new HostBuilder()
            .UseEnvironment(Environments.Production)
            .ConfigureAppConfiguration(configuration => configuration.AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    ["Services:IAMService:BaseUrl"] = "http://127.0.0.1:5100"
                }))
            .ConfigureServices((context, services) => services.AddWorkloadIdentityIamEndpoint(
                context.Configuration.GetSection("Services:IAMService"),
                context.HostingEnvironment))
            .Build();

        await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync());
    }

    private sealed class TestEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;

        public string ApplicationName { get; set; } = "AuthService.Tests";

        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;

        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } =
            new Microsoft.Extensions.FileProviders.NullFileProvider();
    }
}
