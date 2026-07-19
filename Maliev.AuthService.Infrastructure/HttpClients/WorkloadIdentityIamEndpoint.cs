using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Maliev.AuthService.Infrastructure.HttpClients;

/// <summary>Configures the trusted IAM origin used for employee-authorized workload provisioning.</summary>
public sealed class WorkloadIdentityIamEndpointOptions
{
    /// <summary>Gets or sets an optional explicit canonical IAM origin.</summary>
    public string? BaseUrl { get; set; }
}

/// <summary>Resolves and validates the trusted IAM workload-provisioning origin.</summary>
public interface IWorkloadIdentityIamEndpointResolver
{
    /// <summary>Resolves a trusted IAM origin or throws when configuration is unsafe.</summary>
    Uri Resolve(WorkloadIdentityIamEndpointOptions options);
}

/// <summary>Environment-aware resolver for the trusted IAM workload-provisioning origin.</summary>
public sealed class WorkloadIdentityIamEndpointResolver(IHostEnvironment environment)
    : IWorkloadIdentityIamEndpointResolver
{
    /// <inheritdoc/>
    public Uri Resolve(WorkloadIdentityIamEndpointOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrEmpty(options.BaseUrl))
        {
            return new Uri(IsLocalEnvironment
                ? "https+http://IAMService"
                : "https://IAMService");
        }

        var value = options.BaseUrl;
        if (value != value.Trim() ||
            value.EndsWith("/", StringComparison.Ordinal) ||
            !Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            !(uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp) ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment) ||
            uri.AbsolutePath != "/" ||
            value != BuildCanonicalOrigin(uri) ||
            uri.Scheme == Uri.UriSchemeHttp && (!IsLocalEnvironment || !IsExactLoopback(uri.Host)))
        {
            throw new OptionsValidationException(
                nameof(WorkloadIdentityIamEndpointOptions),
                typeof(WorkloadIdentityIamEndpointOptions),
                ["Services:IAMService:BaseUrl must be a canonical trusted IAM origin"]);
        }

        return uri;
    }

    private bool IsLocalEnvironment =>
        environment.IsDevelopment() ||
        string.Equals(environment.EnvironmentName, "Testing", StringComparison.Ordinal);

    private static bool IsExactLoopback(string host) =>
        string.Equals(host, "localhost", StringComparison.Ordinal) ||
        IPAddress.TryParse(host.Trim('[', ']'), out var address) && IPAddress.IsLoopback(address);

    private static string BuildCanonicalOrigin(Uri uri)
    {
        var host = uri.IdnHost;
        if (host.Contains(':', StringComparison.Ordinal))
        {
            host = $"[{host}]";
        }

        return uri.IsDefaultPort
            ? $"{uri.Scheme}://{host}"
            : $"{uri.Scheme}://{host}:{uri.Port}";
    }
}

/// <summary>Registers startup validation and runtime resolution for the trusted IAM origin.</summary>
public static class WorkloadIdentityIamEndpointExtensions
{
    /// <summary>Adds the shared IAM endpoint resolver and fail-fast options validation.</summary>
    public static IServiceCollection AddWorkloadIdentityIamEndpoint(
        this IServiceCollection services,
        IConfigurationSection section,
        IHostEnvironment environment)
    {
        services.AddSingleton<IWorkloadIdentityIamEndpointResolver>(
            new WorkloadIdentityIamEndpointResolver(environment));
        services.AddSingleton<IValidateOptions<WorkloadIdentityIamEndpointOptions>,
            WorkloadIdentityIamEndpointValidator>();
        services.AddOptions<WorkloadIdentityIamEndpointOptions>()
            .Bind(section)
            .ValidateOnStart();
        return services;
    }

    private sealed class WorkloadIdentityIamEndpointValidator(
        IWorkloadIdentityIamEndpointResolver resolver)
        : IValidateOptions<WorkloadIdentityIamEndpointOptions>
    {
        public ValidateOptionsResult Validate(string? name, WorkloadIdentityIamEndpointOptions options)
        {
            try
            {
                _ = resolver.Resolve(options);
                return ValidateOptionsResult.Success;
            }
            catch (OptionsValidationException exception)
            {
                return ValidateOptionsResult.Fail(exception.Failures);
            }
        }
    }
}
