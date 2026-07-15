using System.Reflection;
using Maliev.AuthService.Api.Authorization;
using Maliev.AuthService.Api.Controllers;
using Microsoft.AspNetCore.RateLimiting;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public class ServiceLoginEndpointSecurityTests
{
    [Fact]
    public void ServiceLogin_UsesDedicatedFixedWindowPolicy()
    {
        var method = typeof(AuthenticationController).GetMethod(
            nameof(AuthenticationController.ServiceLogin),
            BindingFlags.Instance | BindingFlags.Public);

        var metadata = method?.GetCustomAttribute<EnableRateLimitingAttribute>();

        Assert.NotNull(metadata);
        Assert.Equal(AuthRateLimitPolicies.ServiceLogin, metadata.PolicyName);
    }
}
