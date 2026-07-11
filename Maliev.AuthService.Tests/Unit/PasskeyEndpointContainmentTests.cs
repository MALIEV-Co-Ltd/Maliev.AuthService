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
        var controller = CreateController(passkeyService.Object);

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
        var controller = CreateController(passkeyService.Object);

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
        var controller = CreateController(passkeyService.Object);

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
        var controller = CreateController(passkeyService.Object);

        var result = await controller.DeletePasskeyCredential(
            Guid.NewGuid(),
            Guid.NewGuid(),
            CancellationToken.None);

        AssertRegistrationUnavailable(result);
        passkeyService.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies every passkey endpoint is restricted to trusted identity-exchange callers.
    /// </summary>
    /// <param name="methodName">The controller action name.</param>
    [Theory]
    [InlineData(nameof(AuthenticationController.BeginPasskeyRegistration))]
    [InlineData(nameof(AuthenticationController.CompletePasskeyRegistration))]
    [InlineData(nameof(AuthenticationController.BeginPasskeyAuthentication))]
    [InlineData(nameof(AuthenticationController.CompletePasskeyAuthentication))]
    [InlineData(nameof(AuthenticationController.ListPasskeyCredentials))]
    [InlineData(nameof(AuthenticationController.DeletePasskeyCredential))]
    public void PasskeyAction_RequiresIdentityExchangePermission(string methodName)
    {
        var method = typeof(AuthenticationController).GetMethod(methodName);

        var permission = method?.GetCustomAttribute<RequirePermissionAttribute>();

        Assert.NotNull(permission);
        Assert.Equal(AuthPermissions.ExchangeIdentities, permission.Permission);
    }

    private static AuthenticationController CreateController(IPasskeyService passkeyService)
    {
        return new AuthenticationController(
            Mock.Of<IAuthenticationService>(),
            Mock.Of<IEmailVerificationService>(),
            passkeyService,
            Mock.Of<IGoogleIdentityNonceService>(),
            new ConfigurationBuilder().Build(),
            NullLogger<AuthenticationController>.Instance);
    }

    private static Mock<IPasskeyService> CreatePasskeyServiceMock()
    {
        var mock = new Mock<IPasskeyService>();
        mock.Setup(service => service.BeginRegistrationAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((PasskeyRegistrationBeginResponse)null!);
        mock.Setup(service => service.CompleteRegistrationAsync(
                It.IsAny<PasskeyRegistrationCompleteRequest>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyRegistrationCompleteResponse(true, null));
        mock.Setup(service => service.ListCredentialsAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyListResponse([]));
        mock.Setup(service => service.DeleteCredentialAsync(
                It.IsAny<Guid>(),
                It.IsAny<Guid>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        return mock;
    }

    private static void AssertRegistrationUnavailable(IActionResult actionResult)
    {
        var result = Assert.IsType<ObjectResult>(actionResult);
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, result.StatusCode);
        var error = Assert.IsType<ErrorResponse>(result.Value);
        Assert.Equal("passkey_registration_unavailable", error.Error);
    }
}
