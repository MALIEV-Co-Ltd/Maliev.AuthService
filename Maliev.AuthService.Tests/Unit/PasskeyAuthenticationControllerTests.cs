using System.Security.Claims;
using Maliev.AuthService.Api.Controllers;
using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Application.DTOs.Response;
using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Domain.Entities;
using Maliev.AuthService.Infrastructure.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

/// <summary>
/// Verifies AuthService binds passkey ceremonies to the configured service caller and application.
/// </summary>
public sealed class PasskeyAuthenticationControllerTests
{
    /// <summary>Verifies an allowed Web BFF caller reaches the service with server identity.</summary>
    [Fact]
    public async Task BeginPasskeyAuthentication_BoundWebCaller_ReturnsOneTimeOptions()
    {
        var passkeyService = new Mock<IPasskeyService>();
        passkeyService.Setup(service => service.BeginAuthenticationAsync(
                It.IsAny<PasskeyAuthBeginRequest>(),
                "WebBff",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthBeginResponse(
                new string('A', 43),
                DateTime.UtcNow.AddMinutes(5),
                "maliev.test",
                new string('B', 43),
                [],
                "required",
                300_000));
        var controller = CreateController(passkeyService.Object, "WebBff");

        var result = await controller.Begin(
            new PasskeyAuthBeginRequest { Application = "web" },
            CancellationToken.None);

        Assert.IsType<OkObjectResult>(result);
        passkeyService.VerifyAll();
    }

    /// <summary>Verifies a saturated or unavailable ceremony store returns one generic retryable response.</summary>
    [Fact]
    public async Task BeginPasskeyAuthentication_CeremonyUnavailable_ReturnsGenericServiceUnavailable()
    {
        var passkeyService = new Mock<IPasskeyService>();
        passkeyService.Setup(service => service.BeginAuthenticationAsync(
                It.IsAny<PasskeyAuthBeginRequest>(),
                "WebBff",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync((PasskeyAuthBeginResponse?)null);
        var controller = CreateController(passkeyService.Object, "WebBff");

        var result = await controller.Begin(
            new PasskeyAuthBeginRequest { Application = "web" },
            CancellationToken.None);

        var response = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, response.StatusCode);
        var error = Assert.IsType<ErrorResponse>(response.Value);
        Assert.Equal("passkey_temporarily_unavailable", error.Error);
        passkeyService.VerifyAll();
    }

    /// <summary>Verifies wrong service/application pairs fail before ceremony creation.</summary>
    [Theory]
    [InlineData("QuoteEngineBff", "web")]
    [InlineData("WebBff", "quote-engine")]
    [InlineData("", "web")]
    public async Task BeginPasskeyAuthentication_UnboundCaller_IsForbidden(
        string serviceName,
        string application)
    {
        var passkeyService = new Mock<IPasskeyService>();
        var controller = CreateController(passkeyService.Object, serviceName);

        var result = await controller.Begin(
            new PasskeyAuthBeginRequest { Application = application },
            CancellationToken.None);

        Assert.IsType<ForbidResult>(result);
        passkeyService.VerifyNoOtherCalls();
    }

    /// <summary>Verifies caller-supplied principal scoping is rejected to prevent enumeration.</summary>
    [Fact]
    public async Task BeginPasskeyAuthentication_PrincipalScopedRequest_IsRejected()
    {
        var passkeyService = new Mock<IPasskeyService>();
        var controller = CreateController(passkeyService.Object, "WebBff");

        var result = await controller.Begin(
            new PasskeyAuthBeginRequest
            {
                Application = "web",
                PrincipalId = Guid.NewGuid()
            },
            CancellationToken.None);

        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        var error = Assert.IsType<ErrorResponse>(badRequest.Value);
        Assert.Equal("passkey_flow_invalid", error.Error);
        passkeyService.VerifyNoOtherCalls();
    }

    /// <summary>Verifies invalid identity and retryable failures have distinct generic HTTP semantics.</summary>
    [Theory]
    [InlineData("passkey_identity_invalid", StatusCodes.Status401Unauthorized)]
    [InlineData("passkey_unavailable", StatusCodes.Status503ServiceUnavailable)]
    [InlineData("passkey_temporarily_unavailable", StatusCodes.Status503ServiceUnavailable)]
    public async Task CompletePasskeyAuthentication_FailedVerification_DoesNotReturnIdentity(
        string internalError,
        int expectedStatus)
    {
        var passkeyService = new Mock<IPasskeyService>();
        passkeyService.Setup(service => service.CompleteAuthenticationAsync(
                It.IsAny<PasskeyAuthCompleteRequest>(),
                "WebBff",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAuthCompleteResponse(false, internalError, null, null));
        var controller = CreateController(passkeyService.Object, "WebBff");

        var result = await controller.Complete(
            new PasskeyAuthCompleteRequest
            {
                Application = "web",
                FlowId = new string('A', 43),
                CredentialId = "credential",
                AuthenticatorData = "data",
                ClientDataJson = "client",
                Signature = "signature",
                UserHandle = "handle"
            },
            CancellationToken.None);

        var response = Assert.IsType<ObjectResult>(result);
        Assert.Equal(expectedStatus, response.StatusCode);
        var error = Assert.IsType<ErrorResponse>(response.Value);
        Assert.Equal(
            expectedStatus == StatusCodes.Status503ServiceUnavailable
                ? "passkey_temporarily_unavailable"
                : "authentication_failed",
            error.Error);
        Assert.DoesNotContain(
            "credential",
            error.ErrorDescription ?? string.Empty,
            StringComparison.OrdinalIgnoreCase);
    }

    private static PasskeyAuthenticationController CreateController(
        IPasskeyService passkeyService,
        string serviceName)
    {
        var options = Options.Create(new PasskeyWebAuthnOptions
        {
            Bindings = new Dictionary<string, PasskeyApplicationBinding>
            {
                ["web"] = new()
                {
                    ServiceName = "WebBff",
                    PrincipalType = UserType.Customer
                }
            }
        });
        var controller = new PasskeyAuthenticationController(
            passkeyService,
            options,
            NullLogger<PasskeyAuthenticationController>.Instance);
        var claims = new List<Claim>
        {
            new("user_type", "service")
        };
        if (!string.IsNullOrWhiteSpace(serviceName))
        {
            claims.Add(new Claim("service_name", serviceName));
        }
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test")),
                TraceIdentifier = "passkey-controller-test"
            }
        };
        return controller;
    }
}
