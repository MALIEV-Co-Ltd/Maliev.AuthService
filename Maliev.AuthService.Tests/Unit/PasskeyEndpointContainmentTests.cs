using System.Reflection;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Maliev.AuthService.Api.Authorization;
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

/// <summary>
/// Verifies the temporary passkey endpoint containment boundary.
/// </summary>
public sealed class PasskeyEndpointContainmentTests
{
    /// <summary>
    /// Verifies passkey registration cannot reach the incomplete registration service.
    /// </summary>
    [Fact]
    public async Task BeginPasskeyRegistration_WhenRegistrationIsUnavailable_ReturnsServiceUnavailableWithoutInvokingService()
    {
        var passkeyService = CreatePasskeyServiceMock();
        var controller = CreateController();

        var result = await controller.BeginPasskeyRegistration(
            new PasskeyRegistrationBeginRequest { PrincipalId = Guid.NewGuid() },
            CancellationToken.None);

        AssertRegistrationUnavailable(result);
        passkeyService.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies passkey registration completion cannot reach the incomplete registration service.
    /// </summary>
    [Fact]
    public async Task CompletePasskeyRegistration_WhenRegistrationIsUnavailable_ReturnsServiceUnavailableWithoutInvokingService()
    {
        var passkeyService = CreatePasskeyServiceMock();
        var controller = CreateController();

        var result = await controller.CompletePasskeyRegistration(
            new PasskeyRegistrationCompleteRequest
            {
                PrincipalId = Guid.NewGuid(),
                CredentialId = "credential-id",
                PublicKey = "public-key",
                DeviceName = "Test device"
            },
            CancellationToken.None);

        AssertRegistrationUnavailable(result);
        passkeyService.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies passkey credential discovery cannot reach the incomplete registration service.
    /// </summary>
    [Fact]
    public async Task ListPasskeyCredentials_WhenRegistrationIsUnavailable_ReturnsServiceUnavailableWithoutInvokingService()
    {
        var passkeyService = CreatePasskeyServiceMock();
        var controller = CreateController();

        var result = await controller.ListPasskeyCredentials(Guid.NewGuid(), CancellationToken.None);

        AssertRegistrationUnavailable(result);
        passkeyService.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies passkey credential deletion cannot reach the incomplete registration service.
    /// </summary>
    [Fact]
    public async Task DeletePasskeyCredential_WhenRegistrationIsUnavailable_ReturnsServiceUnavailableWithoutInvokingService()
    {
        var passkeyService = CreatePasskeyServiceMock();
        var controller = CreateController();

        var result = await controller.DeletePasskeyCredential(
            Guid.NewGuid(),
            Guid.NewGuid(),
            CancellationToken.None);

        AssertRegistrationUnavailable(result);
        passkeyService.VerifyNoOtherCalls();
    }

    /// <summary>Verifies the legacy v1 authentication routes stay present but fail closed.</summary>
    [Fact]
    public void LegacyPasskeyAuthentication_WhenCalled_ReturnsServiceUnavailable()
    {
        var controller = CreateController();

        var begin = controller.BeginPasskeyAuthentication(CancellationToken.None);
        var complete = controller.CompletePasskeyAuthentication(CancellationToken.None);

        AssertAuthenticationUnavailable(begin);
        AssertAuthenticationUnavailable(complete);
    }

    /// <summary>
    /// Verifies every passkey endpoint is restricted to trusted identity-exchange callers.
    /// </summary>
    /// <param name="controllerType">The controller that owns the action.</param>
    /// <param name="methodName">The controller action name.</param>
    [Theory]
    [InlineData(typeof(AuthenticationController), nameof(AuthenticationController.BeginPasskeyRegistration))]
    [InlineData(typeof(AuthenticationController), nameof(AuthenticationController.CompletePasskeyRegistration))]
    [InlineData(typeof(AuthenticationController), nameof(AuthenticationController.BeginPasskeyAuthentication))]
    [InlineData(typeof(AuthenticationController), nameof(AuthenticationController.CompletePasskeyAuthentication))]
    [InlineData(typeof(AuthenticationController), nameof(AuthenticationController.ListPasskeyCredentials))]
    [InlineData(typeof(AuthenticationController), nameof(AuthenticationController.DeletePasskeyCredential))]
    [InlineData(typeof(PasskeyAuthenticationController), nameof(PasskeyAuthenticationController.Begin))]
    [InlineData(typeof(PasskeyAuthenticationController), nameof(PasskeyAuthenticationController.Complete))]
    public void PasskeyAction_RequiresIdentityExchangePermission(Type controllerType, string methodName)
    {
        var method = controllerType.GetMethod(methodName);

        var permission = method?.GetCustomAttribute<RequirePermissionAttribute>();

        Assert.NotNull(permission);
        Assert.Equal(AuthPermissions.ExchangeIdentities, permission.Permission);
    }

    private static AuthenticationController CreateController()
    {
        return new AuthenticationController(
            Mock.Of<IAuthenticationService>(),
            Mock.Of<IEmailVerificationService>(),
            Mock.Of<IGoogleIdentityNonceService>(),
            new ConfigurationBuilder().Build(),
            NullLogger<AuthenticationController>.Instance);
    }

    private static Mock<IPasskeyService> CreatePasskeyServiceMock()
    {
        return new Mock<IPasskeyService>();
    }

    private static void AssertRegistrationUnavailable(IActionResult actionResult)
    {
        var result = Assert.IsType<ObjectResult>(actionResult);
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, result.StatusCode);
        var error = Assert.IsType<ErrorResponse>(result.Value);
        Assert.Equal("passkey_registration_unavailable", error.Error);
    }

    private static void AssertAuthenticationUnavailable(IActionResult actionResult)
    {
        var result = Assert.IsType<ObjectResult>(actionResult);
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, result.StatusCode);
        var error = Assert.IsType<ErrorResponse>(result.Value);
        Assert.Equal("passkey_authentication_unavailable", error.Error);
    }
}
