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

namespace Maliev.AuthService.Tests.Unit;

public class AuthenticationServiceTests : IClassFixture<TestDatabaseFixture>, IAsyncLifetime
{
    private readonly TestDatabaseFixture _fixture;
    private readonly Mock<ITokenGenerator> _tokenGeneratorMock;
    private readonly Mock<ITokenValidator> _tokenValidatorMock;
    private readonly Mock<IRefreshTokenService> _refreshTokenServiceMock;
    private readonly Mock<IAccountLockoutService> _accountLockoutServiceMock;
    private readonly Mock<IRateLimitService> _rateLimitServiceMock;
    private readonly Mock<IIAMClient> _iamClientMock;
    private readonly Mock<ILogger<AuthenticationService>> _loggerMock;
    private readonly Mock<IHttpClientFactory> _httpClientFactoryMock;
    private readonly Mock<IConfiguration> _configurationMock;
    private AuthenticationService? _service;

    public AuthenticationServiceTests(TestDatabaseFixture fixture)
    {
        _fixture = fixture;
        _tokenGeneratorMock = new Mock<ITokenGenerator>();
        _tokenValidatorMock = new Mock<ITokenValidator>();
        _refreshTokenServiceMock = new Mock<IRefreshTokenService>();
        _accountLockoutServiceMock = new Mock<IAccountLockoutService>();
        _rateLimitServiceMock = new Mock<IRateLimitService>();
        _iamClientMock = new Mock<IIAMClient>();
        _loggerMock = new Mock<ILogger<AuthenticationService>>();
        _httpClientFactoryMock = new Mock<IHttpClientFactory>();
        _configurationMock = new Mock<IConfiguration>();
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
            _configurationMock.Object);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task AuthenticateAsync_IAMDisabled_DoesNotCallIAM()
    {
        // Arrange
        var request = new LoginRequest { Username = "test@test.com", Password = "password", UserType = "customer" };
        var ipAddress = "127.0.0.1";

        var iamSectionMock = new Mock<IConfigurationSection>();
        iamSectionMock.Setup(s => s.Value).Returns("false");
        _configurationMock.Setup(c => c.GetSection("Features:IAMIntegrationEnabled")).Returns(iamSectionMock.Object);
        _configurationMock.Setup(c => c["Features:IAMIntegrationEnabled"]).Returns("false");
        _configurationMock.Setup(c => c["CustomerService:BaseUrl"]).Returns("http://customer-service");
        _configurationMock.Setup(c => c["CustomerService:ValidationEndpoint"]).Returns("/validate");

        // Mock HttpClient for validation
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = JsonContent.Create(new { IsValid = true, UserId = Guid.NewGuid(), Email = "test@test.com", Name = "Test" })
            });
        _httpClientFactoryMock.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(new HttpClient(handlerMock.Object));

        _refreshTokenServiceMock.Setup(s => s.CreateRefreshTokenAsync(It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<UserType>(), It.IsAny<string>()))
            .ReturnsAsync((new RefreshToken(), "token"));

        // Act
        await _service!.AuthenticateAsync(request, ipAddress);

        // Assert
        _iamClientMock.Verify(c => c.ResolvePermissionsAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}