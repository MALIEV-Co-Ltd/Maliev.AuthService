using Maliev.AuthService.Api.Models.Request;
using Maliev.AuthService.Api.Models.Response;
using Maliev.AuthService.Api.Models.IAM;
using Maliev.AuthService.Api.Services;
using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Data.Entities;
using Maliev.AuthService.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using Moq.Protected;
using Xunit;
using System.Net;
using System.Net.Http.Json;
using MassTransit;

namespace Maliev.AuthService.Tests.Unit;

public class AuthenticationServiceTests : IClassFixture<TestDatabaseFixture>, IAsyncLifetime
{
    private readonly TestDatabaseFixture _fixture;
    private readonly Mock<ITokenGenerator> _tokenGeneratorMock;
    private readonly Mock<ITokenValidator> _tokenValidatorMock;
    private readonly Mock<IRefreshTokenService> _refreshTokenServiceMock;
    private readonly Mock<IAccountLockoutService> _accountLockoutServiceMock;
    private readonly Mock<IRateLimitService> _rateLimitServiceMock;
    private readonly Mock<IIAMServiceClient> _iamClientMock;
    private readonly Mock<ILogger<AuthenticationService>> _loggerMock;
    private readonly Mock<IHttpClientFactory> _httpClientFactoryMock;
    private readonly Mock<IConfiguration> _configurationMock;
    private readonly Mock<IPublishEndpoint> _publishEndpointMock;
    private readonly Mock<Maliev.AuthService.Api.Services.External.IEmployeeServiceClient> _employeeServiceClientMock;
    private AuthenticationService? _service;

    public AuthenticationServiceTests(TestDatabaseFixture fixture)
    {
        _fixture = fixture;
        _tokenGeneratorMock = new Mock<ITokenGenerator>();
        _tokenValidatorMock = new Mock<ITokenValidator>();
        _refreshTokenServiceMock = new Mock<IRefreshTokenService>();
        _accountLockoutServiceMock = new Mock<IAccountLockoutService>();
        _rateLimitServiceMock = new Mock<IRateLimitService>();
        _iamClientMock = new Mock<IIAMServiceClient>();
        _loggerMock = new Mock<ILogger<AuthenticationService>>();
        _httpClientFactoryMock = new Mock<IHttpClientFactory>();
        _configurationMock = new Mock<IConfiguration>();
        _publishEndpointMock = new Mock<IPublishEndpoint>();
        _employeeServiceClientMock = new Mock<Maliev.AuthService.Api.Services.External.IEmployeeServiceClient>();
    }

    public async Task InitializeAsync()
    {
        await _fixture.InitializeAsync();
        _service = new AuthenticationService(
            _fixture.CreateDbContext(),
            _tokenGeneratorMock.Object,
            _tokenValidatorMock.Object,
            _refreshTokenServiceMock.Object,
            _accountLockoutServiceMock.Object,
            _rateLimitServiceMock.Object,
            _iamClientMock.Object,
            _loggerMock.Object,
            _httpClientFactoryMock.Object,
            _configurationMock.Object,
            _publishEndpointMock.Object,
            _employeeServiceClientMock.Object);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task AuthenticateAsync_InvalidUserType_ThrowsArgumentException()
    {
        // Arrange
        var request = new LoginRequest { Username = "user", Password = "password", UserType = "invalid" };

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(() => _service!.AuthenticateAsync(request, "127.0.0.1"));
    }

    [Fact]
    public async Task AuthenticateAsync_RateLimitExceeded_ReturnsRateLimitExceeded()
    {
        // Arrange
        var request = new LoginRequest { Username = "user", Password = "password", UserType = "customer" };
        var ipAddress = "1.2.3.4";
        var blockedUntil = DateTime.UtcNow.AddMinutes(15);

        _rateLimitServiceMock.Setup(s => s.IsRateLimitExceededAsync(ipAddress))
            .ReturnsAsync(true);
        _rateLimitServiceMock.Setup(s => s.GetBlockedUntilAsync(ipAddress))
            .ReturnsAsync(blockedUntil);

        // Act
        var result = await _service!.AuthenticateAsync(request, ipAddress);

        // Assert
        Assert.False(result.Success);
        Assert.Equal("rate_limit_exceeded", result.ErrorCode);
        Assert.Equal(blockedUntil, result.RetryAfter);
    }

    [Fact]
    public async Task ExchangeGoogleTokenAsync_InvalidDomain_ReturnsInvalidDomain()
    {
        // Arrange
        var request = new GoogleExchangeRequest { Email = "user@gmail.com", FullName = "User" };

        // Act
        var result = await _service!.ExchangeGoogleTokenAsync(request, "127.0.0.1");

        // Assert
        Assert.False(result.Success);
        Assert.Equal("invalid_domain", result.ErrorCode);
    }

    [Fact]
    public async Task ExchangeGoogleTokenAsync_EmployeeNotFound_AutoProvisions()
    {
        // Arrange
        var email = "new.user@maliev.com";
        var request = new GoogleExchangeRequest { Email = email, FullName = "New User" };
        var employeeId = Guid.NewGuid();
        var principalId = Guid.NewGuid();

        _employeeServiceClientMock.Setup(s => s.GetEmployeeByEmailAsync(email))
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.NotFound));

        var provisionResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new
            {
                id = employeeId,
                principalId = principalId,
                email = email,
                fullName = "New User",
                employmentStatus = "Active"
            })
        };
        _employeeServiceClientMock.Setup(s => s.ProvisionEmployeeAsync(It.IsAny<object>()))
            .ReturnsAsync(provisionResponse);

        _iamClientMock.Setup(s => s.ResolvePermissionsAsync(principalId))
            .ReturnsAsync(new PermissionResolutionResponse { Permissions = new List<string> { "read" }, Roles = new List<string> { "user" } });

        _tokenGeneratorMock.Setup(s => s.GenerateAccessToken(principalId, "employee", email, "New User", It.IsAny<IEnumerable<string>>(), It.IsAny<IEnumerable<string>>()))
            .Returns("access-token");

        _refreshTokenServiceMock.Setup(s => s.CreateRefreshTokenAsync(employeeId, principalId, UserType.Employee, email, "New User", It.IsAny<string>()))
            .ReturnsAsync((new RefreshToken(), "refresh-token"));

        // Act
        var result = await _service!.ExchangeGoogleTokenAsync(request, "127.0.0.1");

        // Assert
        Assert.True(result.Success);
        Assert.Equal(principalId, result.PrincipalId);
        Assert.Equal("access-token", result.Response!.AccessToken);
        _employeeServiceClientMock.Verify(s => s.ProvisionEmployeeAsync(It.IsAny<object>()), Times.Once);
    }

    [Fact]
    public async Task ExchangeGoogleTokenAsync_EmployeeLookupFails_ReturnsServiceUnavailable()
    {
        // Arrange
        var email = "user@maliev.com";
        var request = new GoogleExchangeRequest { Email = email };

        _employeeServiceClientMock.Setup(s => s.GetEmployeeByEmailAsync(email))
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.InternalServerError));

        // Act
        var result = await _service!.ExchangeGoogleTokenAsync(request, "127.0.0.1");

        // Assert
        Assert.False(result.Success);
        Assert.Equal("service_unavailable", result.ErrorCode);
    }

    [Fact]
    public async Task ExchangeGoogleTokenAsync_ProvisionFails_ReturnsProvisionFailed()
    {
        // Arrange
        var email = "new.user@maliev.com";
        var request = new GoogleExchangeRequest { Email = email };

        _employeeServiceClientMock.Setup(s => s.GetEmployeeByEmailAsync(email))
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.NotFound));

        _employeeServiceClientMock.Setup(s => s.ProvisionEmployeeAsync(It.IsAny<object>()))
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.BadRequest));

        // Act
        var result = await _service!.ExchangeGoogleTokenAsync(request, "127.0.0.1");

        // Assert
        Assert.False(result.Success);
        Assert.Equal("provision_failed", result.ErrorCode);
    }

    [Fact]
    public async Task ExchangeGoogleTokenAsync_EmployeeTerminated_ReturnsInactiveAccount()
    {
        // Arrange
        var email = "user@maliev.com";
        var request = new GoogleExchangeRequest { Email = email };
        var employeeId = Guid.NewGuid();

        var lookupResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new
            {
                id = employeeId,
                principalId = Guid.NewGuid(),
                email = email,
                fullName = "User",
                employmentStatus = "Terminated"
            })
        };
        _employeeServiceClientMock.Setup(s => s.GetEmployeeByEmailAsync(email))
            .ReturnsAsync(lookupResponse);

        // Act
        var result = await _service!.ExchangeGoogleTokenAsync(request, "127.0.0.1");

        // Assert
        Assert.False(result.Success);
        Assert.Equal("inactive_account", result.ErrorCode);
    }

    [Fact]
    public async Task ExchangeGoogleTokenAsync_LookupTimeout_ReturnsServiceUnavailable()
    {
        // Arrange
        var email = "user@maliev.com";
        var request = new GoogleExchangeRequest { Email = email };

        _employeeServiceClientMock.Setup(s => s.GetEmployeeByEmailAsync(email))
            .ThrowsAsync(new OperationCanceledException());

        // Act
        var result = await _service!.ExchangeGoogleTokenAsync(request, "127.0.0.1");

        // Assert
        Assert.False(result.Success);
        Assert.Equal("service_unavailable", result.ErrorCode);
    }

    [Fact]
    public async Task RefreshTokenAsync_IAMServiceFails_StillReturnsTokens()
    {
        // Arrange
        var refreshTokenValue = "valid-refresh";
        var refreshToken = new RefreshToken
        {
            UserId = Guid.NewGuid(),
            PrincipalId = Guid.NewGuid(),
            UserType = UserType.Employee,
            Email = "user@test.com",
            Name = "User",
            FamilyId = Guid.NewGuid(),
            Family = new TokenFamily { FamilyId = Guid.NewGuid() }
        };

        _refreshTokenServiceMock.Setup(s => s.ValidateRefreshTokenAsync(refreshTokenValue))
            .ReturnsAsync(refreshToken);
        _refreshTokenServiceMock.Setup(s => s.RotateRefreshTokenAsync(refreshToken, It.IsAny<string>()))
            .ReturnsAsync((new RefreshToken(), "new-refresh"));

        _iamClientMock.Setup(s => s.ResolvePermissionsAsync(refreshToken.PrincipalId))
            .ThrowsAsync(new Exception("IAM down"));

        _tokenGeneratorMock.Setup(s => s.GenerateAccessToken(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), null, null))
            .Returns("access-token");

        // Act
        var result = await _service!.RefreshTokenAsync(new RefreshRequest { RefreshToken = refreshTokenValue }, "127.0.0.1");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("access-token", result.AccessToken);
        Assert.Equal("new-refresh", result.RefreshToken);
    }

    [Fact]
    public async Task AuthenticateAsync_ExternalServiceTimeout_ReturnsInvalidCredentials()
    {
        // Arrange
        var request = new LoginRequest { Username = "user", Password = "password", UserType = "customer" };

        _configurationMock.Setup(c => c["CustomerService:ValidationEndpoint"]).Returns("/validate");

        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>()
            )
            .ThrowsAsync(new OperationCanceledException());

        var httpClient = new HttpClient(handlerMock.Object);
        _httpClientFactoryMock.Setup(f => f.CreateClient("ExternalValidation"))
            .Returns(httpClient);

        // Act
        var result = await _service!.AuthenticateAsync(request, "127.0.0.1");

        // Assert
        Assert.False(result.Success);
        Assert.Equal("invalid_credentials", result.ErrorCode);
    }
}
