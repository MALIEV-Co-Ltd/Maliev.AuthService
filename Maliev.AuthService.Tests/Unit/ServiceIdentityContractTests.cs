using System.Reflection;
using System.Net;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Maliev.AuthService.Api.Authorization;
using Maliev.AuthService.Api.Controllers;
using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Application.DTOs.Response;
using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Domain.Entities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Moq;
using System.Security.Claims;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public sealed class ServiceIdentityContractTests
{
    [Theory]
    [InlineData(nameof(ServiceIdentitiesController.Provision), AuthPermissions.ProvisionServiceIdentities)]
    [InlineData(nameof(ServiceIdentitiesController.Get), AuthPermissions.ReadServiceIdentities)]
    [InlineData(nameof(ServiceIdentitiesController.Rotate), AuthPermissions.RotateServiceIdentities)]
    [InlineData(nameof(ServiceIdentitiesController.Revoke), AuthPermissions.RevokeServiceIdentities)]
    public void Endpoint_DeclaresDedicatedPermission(string methodName, string expectedPermission)
    {
        var method = typeof(ServiceIdentitiesController).GetMethod(methodName);

        var permission = method?.GetCustomAttribute<RequirePermissionAttribute>();

        Assert.NotNull(permission);
        Assert.Equal(expectedPermission, permission.Permission);
        Assert.True(permission.IsCritical);
        Assert.True(permission.RequireLiveCheck);
    }

    [Fact]
    public void CredentialVersion_CannotAuthenticateWhilePendingOrExpired()
    {
        var now = new DateTimeOffset(2026, 7, 16, 0, 0, 0, TimeSpan.Zero);
        var version = new ServiceCredentialVersion
        {
            Status = ServiceCredentialVersionStatus.Pending,
            HardExpiresAt = now.AddHours(1)
        };

        Assert.False(version.CanAuthenticate(now));

        version.Status = ServiceCredentialVersionStatus.Active;
        version.HardExpiresAt = now;
        Assert.False(version.CanAuthenticate(now));
    }

    [Theory]
    [InlineData(ServiceCredentialVersionStatus.Active)]
    [InlineData(ServiceCredentialVersionStatus.Grace)]
    public void CredentialVersion_ActiveOrGraceBeforeExpiry_CanAuthenticate(
        ServiceCredentialVersionStatus status)
    {
        var now = new DateTimeOffset(2026, 7, 16, 0, 0, 0, TimeSpan.Zero);
        var version = new ServiceCredentialVersion
        {
            Status = status,
            HardExpiresAt = now.AddMinutes(1),
            GraceExpiresAt = status == ServiceCredentialVersionStatus.Grace
                ? now.AddSeconds(30)
                : null
        };

        Assert.True(version.CanAuthenticate(now));
    }

    [Fact]
    public async Task Provision_ExactEmployeeSubject_ForwardsOriginalBearer()
    {
        var actorId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        var manager = new Mock<IServiceIdentityManager>(MockBehavior.Strict);
        var request = new ProvisionServiceIdentityRequest
        {
            ProfileVersion = 1,
            OperationId = Guid.NewGuid(),
            ServiceName = "Auth Service"
        };
        manager.Setup(service => service.ProvisionAsync(
                "auth",
                request,
                actorId,
                "employee-token",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(NewResponse());
        var controller = CreateController(manager.Object,
            new Claim("user_type", "employee"),
            new Claim("sub", actorId.ToString("D")));
        controller.Request.Headers.Authorization = "Bearer employee-token";

        var result = await controller.Provision("auth", request, CancellationToken.None);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal("no-store", controller.Response.Headers.CacheControl);
        Assert.Equal("no-cache", controller.Response.Headers.Pragma);
        manager.VerifyAll();
    }

    [Fact]
    public async Task Provision_DuplicateSubjectOrServiceIdentity_IsForbiddenBeforeManager()
    {
        var manager = new Mock<IServiceIdentityManager>(MockBehavior.Strict);
        var actorId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        var request = new ProvisionServiceIdentityRequest
        {
            ProfileVersion = 1,
            OperationId = Guid.NewGuid(),
            ServiceName = "Auth Service"
        };
        var controller = CreateController(manager.Object,
            new Claim("user_type", "service"),
            new Claim("sub", actorId.ToString("D")),
            new Claim("sub", Guid.NewGuid().ToString("D")));
        controller.Request.Headers.Authorization = "Bearer service-token";

        var result = await controller.Provision("auth", request, CancellationToken.None);

        Assert.IsType<ForbidResult>(result);
        manager.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Provision_IamTimeoutWithoutCallerCancellation_ReturnsServiceUnavailable()
    {
        var actorId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        var request = new ProvisionServiceIdentityRequest
        {
            ProfileVersion = 1,
            OperationId = Guid.NewGuid(),
            ServiceName = "Auth Service"
        };
        var manager = new Mock<IServiceIdentityManager>(MockBehavior.Strict);
        manager.Setup(service => service.ProvisionAsync(
                "auth",
                request,
                actorId,
                "employee-token",
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new TaskCanceledException("IAM timeout"));
        var controller = CreateController(manager.Object,
            new Claim("user_type", "employee"),
            new Claim("sub", actorId.ToString("D")));
        controller.Request.Headers.Authorization = "Bearer employee-token";

        var result = await controller.Provision("auth", request, CancellationToken.None);

        var unavailable = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, unavailable.StatusCode);
    }

    [Theory]
    [InlineData(HttpStatusCode.Forbidden, StatusCodes.Status403Forbidden)]
    [InlineData(HttpStatusCode.Conflict, StatusCodes.Status409Conflict)]
    public async Task Provision_IamAuthorizationOrConflict_PreservesSafeStatus(
        HttpStatusCode iamStatus,
        int expectedStatus)
    {
        var actorId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        var request = new ProvisionServiceIdentityRequest
        {
            ProfileVersion = 1,
            OperationId = Guid.NewGuid(),
            ServiceName = "Auth Service"
        };
        var manager = new Mock<IServiceIdentityManager>(MockBehavior.Strict);
        manager.Setup(service => service.ProvisionAsync(
                "auth",
                request,
                actorId,
                "employee-token",
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("untrusted upstream body", null, iamStatus));
        var controller = CreateController(manager.Object,
            new Claim("user_type", "employee"),
            new Claim("sub", actorId.ToString("D")));
        controller.Request.Headers.Authorization = "Bearer employee-token";

        var result = await controller.Provision("auth", request, CancellationToken.None);

        if (expectedStatus == StatusCodes.Status403Forbidden)
        {
            Assert.IsType<ForbidResult>(result);
        }
        else
        {
            var status = Assert.IsAssignableFrom<IStatusCodeActionResult>(result);
            Assert.Equal(expectedStatus, status.StatusCode);
        }

        Assert.DoesNotContain("untrusted upstream body", result.ToString(), StringComparison.Ordinal);
    }

    private static ServiceIdentitiesController CreateController(
        IServiceIdentityManager manager,
        params Claim[] claims) => new(manager)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test"))
                }
            }
        };

    private static ServiceIdentityResponse NewResponse() => new()
    {
        WorkloadId = "auth",
        ClientId = "service-auth",
        PrincipalId = Guid.Parse("11111111-1111-1111-1111-111111111111"),
        ProfileVersion = 1,
        RoleId = "roles.workloads.auth.v1",
        IsActive = true,
        CredentialVersion = 1,
        ClientSecret = "one-time-secret",
        SecretRetrievable = true,
        HardExpiresAt = DateTimeOffset.UtcNow.AddDays(1)
    };
}
