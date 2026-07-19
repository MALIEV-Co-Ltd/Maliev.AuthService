using System.Reflection;
using Maliev.AuthService.Api.Controllers;
using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Application.DTOs.Response;
using Maliev.AuthService.Application.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public class ServiceLoginEndpointSecurityTests
{
    [Fact]
    public void ServiceLogin_HasPreBindingRequestSizeLimit()
    {
        var method = typeof(AuthenticationController).GetMethod(
            nameof(AuthenticationController.ServiceLogin),
            BindingFlags.Instance | BindingFlags.Public);

        var metadata = method?.GetCustomAttribute<RequestSizeLimitAttribute>();

        Assert.NotNull(metadata);
        Assert.Equal(4096, ((Microsoft.AspNetCore.Http.Metadata.IRequestSizeLimitMetadata)metadata).MaxRequestBodySize);
    }

    [Fact]
    public async Task ServiceLogin_WhenDistributedLimiterUnavailable_Returns503WithoutAuthenticating()
    {
        var authentication = new Mock<IAuthenticationService>();
        var limiter = new Mock<IServiceLoginRateLimiter>();
        limiter.Setup(service => service.TryAcquireAsync(
                It.IsAny<string>(),
                It.IsAny<System.Net.IPAddress?>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ServiceLoginRateLimitResult(false, false, 0));
        var controller = new AuthenticationController(
            authentication.Object,
            Mock.Of<IEmailVerificationService>(),
            Mock.Of<IGoogleIdentityNonceService>(),
            new ConfigurationBuilder().Build(),
            NullLogger<AuthenticationController>.Instance,
            limiter.Object)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };

        var action = await controller.ServiceLogin(new ServiceLoginRequest
        {
            ClientId = "service-dev-customer-api",
            ClientSecret = "dummy_service_secret_for_unit_test"
        }, CancellationToken.None);

        var result = Assert.IsType<ObjectResult>(action);
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, result.StatusCode);
        Assert.Equal("service_unavailable", Assert.IsType<ErrorResponse>(result.Value).Error);
        authentication.Verify(service => service.AuthenticateServiceAsync(
            It.IsAny<ServiceLoginRequest>(),
            It.IsAny<string?>(),
            It.IsAny<CancellationToken>()), Times.Never);
    }
}
