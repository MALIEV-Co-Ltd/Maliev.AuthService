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
            _publishEndpointMock.Object);
    }

    public Task DisposeAsync() => Task.CompletedTask;

}
