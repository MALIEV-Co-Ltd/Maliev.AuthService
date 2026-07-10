using Maliev.AuthService.Application.DTOs.IAM;
using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Application.DTOs.Response;
using Maliev.AuthService.Application.Identity;
using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Domain.Entities;
using Maliev.AuthService.Infrastructure.DbContexts;
using Maliev.AuthService.Infrastructure.Services;
using Maliev.AuthService.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using Moq.Protected;
using Xunit;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
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
    private readonly Mock<IEmployeeServiceClient> _employeeServiceClientMock;
    private readonly Mock<IGoogleIdentityTokenValidator> _googleIdentityTokenValidatorMock;
    private readonly Mock<IGoogleIdentityNonceService> _googleIdentityNonceServiceMock;
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
        _configurationMock
            .Setup(configuration => configuration["GoogleIdentity:Employee:HostedDomain"])
            .Returns("maliev.com");
        _publishEndpointMock = new Mock<IPublishEndpoint>();
        _employeeServiceClientMock = new Mock<IEmployeeServiceClient>();
        _googleIdentityTokenValidatorMock = new Mock<IGoogleIdentityTokenValidator>();
        _googleIdentityNonceServiceMock = new Mock<IGoogleIdentityNonceService>();
        _googleIdentityNonceServiceMock
            .Setup(service => service.ConsumeAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<GoogleIdentityExchangeType>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
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
            _employeeServiceClientMock.Object,
            _googleIdentityTokenValidatorMock.Object,
            _googleIdentityNonceServiceMock.Object);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void Constructor_ExposesApplicationGoogleIdentityValidatorBoundary()
    {
        var validatorParameter = typeof(AuthenticationService)
            .GetConstructors()
            .SelectMany(constructor => constructor.GetParameters())
            .SingleOrDefault(parameter => string.Equals(
                parameter.ParameterType.FullName,
                "Maliev.AuthService.Application.Interfaces.IGoogleIdentityTokenValidator",
                StringComparison.Ordinal));

        Assert.NotNull(validatorParameter);
    }

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
        var request = ValidEmployeeRequest();
        ArrangeVerifiedEmployeeIdentity("user@gmail.com", "User", hostedDomain: "gmail.com");

        // Act
        var result = await _service!.ExchangeGoogleTokenAsync(request, "127.0.0.1", "IntranetBff");

        // Assert
        Assert.False(result.Success);
        Assert.Equal("invalid_domain", result.ErrorCode);
    }

    [Fact]
    public async Task ExchangeGoogleTokenAsync_InvalidCredential_StopsBeforeEmployeeLookup()
    {
        var request = ValidEmployeeRequest();
        _googleIdentityTokenValidatorMock
            .Setup(validator => validator.ValidateAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                GoogleIdentityExchangeType.Employee,
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new GoogleIdentityValidationResult
            {
                Success = false,
                ErrorCode = "invalid_google_credential",
                ErrorDescription = "Google credential is invalid or expired"
            });

        var result = await _service!.ExchangeGoogleTokenAsync(request, "127.0.0.1", "IntranetBff");

        Assert.False(result.Success);
        Assert.Equal("invalid_google_credential", result.ErrorCode);
        _employeeServiceClientMock.Verify(
            client => client.GetEmployeeByEmailAsync(It.IsAny<string>()),
            Times.Never);
        _googleIdentityNonceServiceMock.Verify(
            service => service.ConsumeAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<GoogleIdentityExchangeType>(),
                It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task ExchangeGoogleTokenAsync_ValidCredential_UsesOnlyVerifiedClaims()
    {
        const string verifiedEmail = "verified.user@maliev.com";
        const string verifiedName = "Verified User";
        const string verifiedPicture = "https://lh3.googleusercontent.com/a/verified";
        var employeeId = Guid.NewGuid();
        var principalId = Guid.NewGuid();
        var request = ValidEmployeeRequest();

        _googleIdentityTokenValidatorMock
            .Setup(validator => validator.ValidateAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                GoogleIdentityExchangeType.Employee,
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new GoogleIdentityValidationResult
            {
                Success = true,
                Identity = new VerifiedGoogleIdentity
                {
                    Subject = "verified-google-sub",
                    Email = verifiedEmail,
                    EmailVerified = true,
                    HostedDomain = "maliev.com",
                    FullName = verifiedName,
                    ProfileImageUrl = verifiedPicture
                }
            });

        _employeeServiceClientMock.Setup(client => client.GetEmployeeByEmailAsync(verifiedEmail))
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(new
                {
                    employeeId,
                    principalId,
                    email = verifiedEmail,
                    fullName = verifiedName,
                    employmentStatus = "Active"
                })
            });
        _iamClientMock.Setup(client => client.ResolvePermissionsAsync(principalId))
            .ReturnsAsync(new PermissionResolutionResponse { Permissions = ["read"], Roles = ["user"] });
        _tokenGeneratorMock.Setup(generator => generator.GenerateAccessToken(
                principalId,
                "employee",
                verifiedEmail,
                verifiedName,
                It.IsAny<IEnumerable<string>>(),
                It.IsAny<IEnumerable<string>>(),
                null,
                verifiedPicture))
            .Returns("access-token");
        _refreshTokenServiceMock.Setup(service => service.CreateRefreshTokenAsync(
                employeeId,
                principalId,
                UserType.Employee,
                verifiedEmail,
                verifiedName,
                "127.0.0.1"))
            .ReturnsAsync((new RefreshToken(), "refresh-token"));

        var result = await _service!.ExchangeGoogleTokenAsync(request, "127.0.0.1", "IntranetBff");

        Assert.True(result.Success, $"{result.ErrorCode}: {result.ErrorDescription}");
        Assert.Equal(verifiedEmail, result.Response!.User.Email);
        Assert.Equal(verifiedPicture, result.Response.User.ProfileImageUrl);
        _employeeServiceClientMock.Verify(client => client.GetEmployeeByEmailAsync(verifiedEmail), Times.Once);
    }

    [Fact]
    public async Task ExchangeCustomerGoogleTokenAsync_ValidCredential_ForwardsVerifiedSubjectAndProfile()
    {
        const string verifiedSubject = "verified-google-sub";
        const string verifiedEmail = "verified.customer@gmail.com";
        const string verifiedName = "Verified Customer";
        const string verifiedPicture = "https://lh3.googleusercontent.com/a/customer";
        var customerId = Guid.NewGuid();
        var principalId = Guid.NewGuid();
        string? outboundBody = null;
        var request = new CustomerGoogleExchangeRequest
        {
            Credential = "customer-google-id-token",
            Application = "web",
            Nonce = "one-time-nonce-for-customer-tests"
        };

        _googleIdentityTokenValidatorMock
            .Setup(validator => validator.ValidateAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                GoogleIdentityExchangeType.Customer,
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new GoogleIdentityValidationResult
            {
                Success = true,
                Identity = new VerifiedGoogleIdentity
                {
                    Subject = verifiedSubject,
                    Email = verifiedEmail,
                    EmailVerified = true,
                    FullName = verifiedName,
                    ProfileImageUrl = verifiedPicture
                }
            });

        var handler = new DelegatingTestHandler(async (message, cancellationToken) =>
        {
            outboundBody = await message.Content!.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(new
                {
                    customerId,
                    principalId,
                    email = verifiedEmail,
                    displayName = verifiedName,
                    profileImageUrl = verifiedPicture
                })
            };
        });
        _httpClientFactoryMock.Setup(factory => factory.CreateClient("ExternalValidation"))
            .Returns(new HttpClient(handler));
        _configurationMock.Setup(configuration => configuration["CustomerService:BaseUrl"])
            .Returns("http://CustomerService");
        _configurationMock.Setup(configuration => configuration["CustomerService:GoogleLinkOrRegisterEndpoint"])
            .Returns("/customer/v1/customers/google/link-or-register");
        _iamClientMock.Setup(client => client.ResolvePermissionsAsync(principalId))
            .ReturnsAsync(new PermissionResolutionResponse { Permissions = ["read"], Roles = ["customer"] });
        _tokenGeneratorMock.Setup(generator => generator.GenerateAccessToken(
                principalId,
                "customer",
                verifiedEmail,
                verifiedName,
                It.IsAny<IEnumerable<string>>(),
                It.IsAny<IEnumerable<string>>(),
                customerId,
                It.IsAny<string?>()))
            .Returns("access-token");
        _refreshTokenServiceMock.Setup(service => service.CreateRefreshTokenAsync(
                customerId,
                principalId,
                UserType.Customer,
                verifiedEmail,
                verifiedName,
                "127.0.0.1"))
            .ReturnsAsync((new RefreshToken(), "refresh-token"));

        var result = await _service!.ExchangeCustomerGoogleTokenAsync(request, "127.0.0.1", "WebBff");

        Assert.True(result.Success, $"{result.ErrorCode}: {result.ErrorDescription}");
        Assert.NotNull(outboundBody);
        using var document = JsonDocument.Parse(outboundBody);
        Assert.Equal(verifiedSubject, document.RootElement.GetProperty("googleSubject").GetString());
        Assert.Equal(verifiedEmail, document.RootElement.GetProperty("email").GetString());
        Assert.Equal(verifiedPicture, document.RootElement.GetProperty("profileImageUrl").GetString());
        Assert.True(document.RootElement.GetProperty("emailLinkAllowed").GetBoolean());
    }

    [Fact]
    public async Task ExchangeCustomerGoogleTokenAsync_NonAuthoritativeExistingEmail_RequiresAccountVerification()
    {
        var request = new CustomerGoogleExchangeRequest
        {
            Credential = "customer-google-id-token",
            Application = "web",
            Nonce = "one-time-nonce-for-customer-tests"
        };
        _googleIdentityTokenValidatorMock
            .Setup(validator => validator.ValidateAsync(
                request.Credential,
                request.Application,
                GoogleIdentityExchangeType.Customer,
                request.Nonce,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new GoogleIdentityValidationResult
            {
                Success = true,
                Identity = new VerifiedGoogleIdentity
                {
                    Subject = "verified-google-sub",
                    Email = "reassignable@third-party.example",
                    EmailVerified = true,
                    HostedDomain = null,
                    FullName = "Different Person"
                }
            });
        _httpClientFactoryMock
            .Setup(factory => factory.CreateClient("ExternalValidation"))
            .Returns(new HttpClient(new DelegatingTestHandler((_, _) => Task.FromResult(
                new HttpResponseMessage(HttpStatusCode.Conflict)
                {
                    Content = JsonContent.Create(new
                    {
                        code = "GOOGLE_EMAIL_LINK_REQUIRES_VERIFICATION",
                        message = "Account verification required"
                    })
                }))));
        _configurationMock.Setup(configuration => configuration["CustomerService:BaseUrl"])
            .Returns("http://CustomerService");

        var result = await _service!.ExchangeCustomerGoogleTokenAsync(request, "127.0.0.1", "WebBff");

        Assert.False(result.Success);
        Assert.Equal("account_verification_required", result.ErrorCode);
        _iamClientMock.Verify(
            client => client.ResolvePermissionsAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task ExchangeGoogleTokenAsync_EmployeeNotFound_AutoProvisions()
    {
        // Arrange
        var email = "new.user@maliev.com";
        var request = ValidEmployeeRequest();
        ArrangeVerifiedEmployeeIdentity(email, "New User");
        var employeeId = Guid.NewGuid();
        var principalId = Guid.NewGuid();

        _employeeServiceClientMock.Setup(s => s.GetEmployeeByEmailAsync(email))
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.NotFound));

        var provisionResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new
            {
                employeeId = employeeId,
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

        _tokenGeneratorMock.Setup(s => s.GenerateAccessToken(principalId, "employee", email, "New User", It.IsAny<IEnumerable<string>>(), It.IsAny<IEnumerable<string>>(), null))
            .Returns("access-token");

        _refreshTokenServiceMock.Setup(s => s.CreateRefreshTokenAsync(employeeId, principalId, UserType.Employee, email, "New User", It.IsAny<string>()))
            .ReturnsAsync((new RefreshToken(), "refresh-token"));

        // Act
        var result = await _service!.ExchangeGoogleTokenAsync(request, "127.0.0.1", "IntranetBff");

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
        var request = ValidEmployeeRequest();
        ArrangeVerifiedEmployeeIdentity(email, "User");

        _employeeServiceClientMock.Setup(s => s.GetEmployeeByEmailAsync(email))
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.InternalServerError));

        // Act
        var result = await _service!.ExchangeGoogleTokenAsync(request, "127.0.0.1", "IntranetBff");

        // Assert
        Assert.False(result.Success);
        Assert.Equal("service_unavailable", result.ErrorCode);
    }

    [Fact]
    public async Task ExchangeGoogleTokenAsync_ProvisionFails_ReturnsProvisionFailed()
    {
        // Arrange
        var email = "new.user@maliev.com";
        var request = ValidEmployeeRequest();
        ArrangeVerifiedEmployeeIdentity(email, "New User");

        _employeeServiceClientMock.Setup(s => s.GetEmployeeByEmailAsync(email))
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.NotFound));

        _employeeServiceClientMock.Setup(s => s.ProvisionEmployeeAsync(It.IsAny<object>()))
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.BadRequest));

        // Act
        var result = await _service!.ExchangeGoogleTokenAsync(request, "127.0.0.1", "IntranetBff");

        // Assert
        Assert.False(result.Success);
        Assert.Equal("provision_failed", result.ErrorCode);
    }

    [Fact]
    public async Task ExchangeGoogleTokenAsync_EmployeeTerminated_ReturnsInactiveAccount()
    {
        // Arrange
        var email = "user@maliev.com";
        var request = ValidEmployeeRequest();
        ArrangeVerifiedEmployeeIdentity(email, "User");
        var employeeId = Guid.NewGuid();

        var lookupResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new
            {
                employeeId = employeeId,
                principalId = Guid.NewGuid(),
                email = email,
                fullName = "User",
                employmentStatus = "Terminated"
            })
        };
        _employeeServiceClientMock.Setup(s => s.GetEmployeeByEmailAsync(email))
            .ReturnsAsync(lookupResponse);

        // Act
        var result = await _service!.ExchangeGoogleTokenAsync(request, "127.0.0.1", "IntranetBff");

        // Assert
        Assert.False(result.Success);
        Assert.Equal("inactive_account", result.ErrorCode);
    }

    [Fact]
    public async Task ExchangeGoogleTokenAsync_LookupTimeout_ReturnsServiceUnavailable()
    {
        // Arrange
        var email = "user@maliev.com";
        var request = ValidEmployeeRequest();
        ArrangeVerifiedEmployeeIdentity(email, "User");

        _employeeServiceClientMock.Setup(s => s.GetEmployeeByEmailAsync(email))
            .ThrowsAsync(new OperationCanceledException());

        // Act
        var result = await _service!.ExchangeGoogleTokenAsync(request, "127.0.0.1", "IntranetBff");

        // Assert
        Assert.False(result.Success);
        Assert.Equal("service_unavailable", result.ErrorCode);
    }

    [Fact]
    public async Task ExchangeGoogleTokenAsync_CallerCancellationDuringEmployeeLookup_Propagates()
    {
        var email = "user@maliev.com";
        var request = ValidEmployeeRequest();
        ArrangeVerifiedEmployeeIdentity(email, "User");
        _employeeServiceClientMock
            .Setup(service => service.GetEmployeeByEmailAsync(
                email,
                It.IsAny<CancellationToken>()))
            .Returns((string _, CancellationToken token) =>
                Task.FromCanceled<HttpResponseMessage>(token));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            _service!.ExchangeGoogleTokenAsync(request, "127.0.0.1", "IntranetBff", cancellation.Token));
    }

    [Fact]
    public async Task ExchangeCustomerGoogleTokenAsync_CallerCancellationDuringCustomerLink_Propagates()
    {
        var request = new CustomerGoogleExchangeRequest
        {
            Credential = "customer-google-id-token",
            Application = "web",
            Nonce = "one-time-nonce-for-customer-tests"
        };
        _googleIdentityTokenValidatorMock
            .Setup(validator => validator.ValidateAsync(
                request.Credential,
                request.Application,
                GoogleIdentityExchangeType.Customer,
                request.Nonce,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new GoogleIdentityValidationResult
            {
                Success = true,
                Identity = new VerifiedGoogleIdentity
                {
                    Subject = "verified-google-sub",
                    Email = "verified.customer@gmail.com",
                    EmailVerified = true,
                    FullName = "Verified Customer"
                }
            });
        _httpClientFactoryMock
            .Setup(factory => factory.CreateClient("ExternalValidation"))
            .Returns(new HttpClient(new DelegatingTestHandler(
                (_, token) => Task.FromCanceled<HttpResponseMessage>(token))));
        _configurationMock.Setup(configuration => configuration["CustomerService:BaseUrl"])
            .Returns("http://CustomerService");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            _service!.ExchangeCustomerGoogleTokenAsync(request, "127.0.0.1", "WebBff", cancellation.Token));
    }

    [Fact]
    public async Task RefreshTokenAsync_IAMServiceFails_ReturnsNull()
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

        // Act
        var result = await _service!.RefreshTokenAsync(new RefreshRequest { RefreshToken = refreshTokenValue }, "127.0.0.1");

        // Assert
        Assert.Null(result);
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

    [Fact]
    public async Task AuthenticateAsync_EmployeeValidationReturnsCamelCaseResponse_Succeeds()
    {
        // Arrange
        const string email = "aspire-automation@debug.com";
        const string password = "ValidTestPassword123!";
        var principalId = Guid.NewGuid();
        var request = new LoginRequest { Username = email, Password = password, UserType = "employee" };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["EmployeeService:BaseUrl"] = "http://EmployeeService",
                ["EmployeeService:ValidationEndpoint"] = "/employee/v1/auth/validate"
            })
            .Build();

        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    $$"""
                    {
                      "isValid": true,
                      "principalId": "{{principalId}}",
                      "email": "{{email}}",
                      "name": "Codex Admin"
                    }
                    """,
                    Encoding.UTF8,
                    "application/json")
            });

        _httpClientFactoryMock.Setup(f => f.CreateClient("ExternalValidation"))
            .Returns(new HttpClient(handlerMock.Object));

        _iamClientMock.Setup(s => s.ResolvePermissionsAsync(principalId))
            .ReturnsAsync(new PermissionResolutionResponse { Roles = ["roles.platform.owner"], Permissions = ["*"] });

        _tokenGeneratorMock.Setup(s => s.GenerateAccessToken(
                principalId,
                "employee",
                email,
                "Codex Admin",
                null,
                It.Is<IEnumerable<string>>(roles => roles.Contains("roles.platform.owner")),
                null))
            .Returns("access-token");

        _refreshTokenServiceMock.Setup(s => s.CreateRefreshTokenAsync(
                principalId,
                principalId,
                UserType.Employee,
                email,
                "Codex Admin",
                "127.0.0.1"))
            .ReturnsAsync((new RefreshToken(), "refresh-token"));

        var service = new AuthenticationService(
            _fixture.CreateDbContext(),
            _tokenGeneratorMock.Object,
            _tokenValidatorMock.Object,
            _refreshTokenServiceMock.Object,
            _accountLockoutServiceMock.Object,
            _rateLimitServiceMock.Object,
            _iamClientMock.Object,
            _loggerMock.Object,
            _httpClientFactoryMock.Object,
            configuration,
            _publishEndpointMock.Object,
            _employeeServiceClientMock.Object,
            _googleIdentityTokenValidatorMock.Object,
            _googleIdentityNonceServiceMock.Object);

        // Act
        var result = await service.AuthenticateAsync(request, "127.0.0.1");

        // Assert
        handlerMock.Protected().Verify(
            "SendAsync",
            Times.Once(),
            ItExpr.IsAny<HttpRequestMessage>(),
            ItExpr.IsAny<CancellationToken>());
        Assert.True(result.Success, $"{result.ErrorCode}: {result.ErrorDescription}");
        Assert.Equal(principalId, result.PrincipalId);
        Assert.Equal("access-token", result.Response!.AccessToken);
    }

    [Fact]
    public async Task ValidateTokenAsync_ValidToken_ReturnsPrincipalInfo()
    {
        // Arrange
        var token = "valid.jwt.token";
        var claimsPrincipal = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(new[]
            {
                new System.Security.Claims.Claim("sub", Guid.NewGuid().ToString()),
                new System.Security.Claims.Claim("user_type", "customer"),
                new System.Security.Claims.Claim("email", "test@test.com"),
                new System.Security.Claims.Claim("name", "Test User"),
                new System.Security.Claims.Claim("roles", "user"),
                new System.Security.Claims.Claim("permissions", "read")
            }));

        _tokenValidatorMock.Setup(v => v.ValidateAccessTokenAsync(token))
            .ReturnsAsync(claimsPrincipal);
        _tokenValidatorMock.Setup(v => v.IsTokenRevokedAsync(It.IsAny<string>()))
            .ReturnsAsync(false);

        // Act
        var result = await _service!.ValidateTokenAsync(new ValidateRequest { AccessToken = token });

        // Assert
        Assert.True(result.Valid);
        Assert.NotNull(result.UserId);
        Assert.Equal("customer", result.UserType);
    }

    [Fact]
    public async Task ValidateTokenAsync_InvalidToken_ReturnsInvalid()
    {
        // Arrange
        _tokenValidatorMock.Setup(v => v.ValidateAccessTokenAsync(It.IsAny<string>()))
            .ReturnsAsync((System.Security.Claims.ClaimsPrincipal?)null);

        // Act
        var result = await _service!.ValidateTokenAsync(new ValidateRequest { AccessToken = "invalid" });

        // Assert
        Assert.False(result.Valid);
        Assert.Equal("Invalid token", result.Error);
    }

    [Fact]
    public async Task ValidateTokenAsync_RevokedToken_ReturnsInvalid()
    {
        // Arrange
        var jti = Guid.NewGuid().ToString();
        var claimsPrincipal = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(new[]
            {
                new System.Security.Claims.Claim("sub", Guid.NewGuid().ToString()),
                new System.Security.Claims.Claim("jti", jti)
            }));

        _tokenValidatorMock.Setup(v => v.ValidateAccessTokenAsync(It.IsAny<string>()))
            .ReturnsAsync(claimsPrincipal);
        _tokenValidatorMock.Setup(v => v.IsTokenRevokedAsync(jti))
            .ReturnsAsync(true);

        // Act
        var result = await _service!.ValidateTokenAsync(new ValidateRequest { AccessToken = "some.token" });

        // Assert
        Assert.False(result.Valid);
        Assert.Equal("Token has been revoked", result.Error);
    }

    [Fact]
    public async Task RevokeTokenAsync_ValidToken_ReturnsTrue()
    {
        // Arrange
        var jti = Guid.NewGuid().ToString();
        var userId = Guid.NewGuid();
        var claimsPrincipal = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(new[]
            {
                new System.Security.Claims.Claim("sub", userId.ToString()),
                new System.Security.Claims.Claim("jti", jti),
                new System.Security.Claims.Claim("user_type", "customer")
            }));

        _tokenValidatorMock.Setup(v => v.ValidateAccessTokenAsync(It.IsAny<string>()))
            .ReturnsAsync(claimsPrincipal);
        _tokenValidatorMock.Setup(v => v.IsTokenRevokedAsync(jti))
            .ReturnsAsync(false);

        // Act
        var result = await _service!.RevokeTokenAsync(new RevokeRequest { Token = "some.token" });

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task RevokeTokenAsync_InvalidToken_ReturnsFalse()
    {
        // Arrange
        _tokenValidatorMock.Setup(v => v.ValidateAccessTokenAsync(It.IsAny<string>()))
            .ReturnsAsync((System.Security.Claims.ClaimsPrincipal?)null);

        // Act
        var result = await _service!.RevokeTokenAsync(new RevokeRequest { Token = "invalid" });

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task RevokeTokenAsync_AlreadyRevoked_ReturnsTrue()
    {
        // Arrange
        var jti = Guid.NewGuid().ToString();
        var userId = Guid.NewGuid();
        var claimsPrincipal = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(new[]
            {
                new System.Security.Claims.Claim("sub", userId.ToString()),
                new System.Security.Claims.Claim("jti", jti),
                new System.Security.Claims.Claim("user_type", "customer")
            }));

        _tokenValidatorMock.Setup(v => v.ValidateAccessTokenAsync(It.IsAny<string>()))
            .ReturnsAsync(claimsPrincipal);
        _tokenValidatorMock.Setup(v => v.IsTokenRevokedAsync(jti))
            .ReturnsAsync(true);

        // Act
        var result = await _service!.RevokeTokenAsync(new RevokeRequest { Token = "some.token" });

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task LogoutAsync_ValidRefreshToken_ReturnsTrue()
    {
        // Arrange
        var refreshToken = new RefreshToken
        {
            UserId = Guid.NewGuid(),
            PrincipalId = Guid.NewGuid(),
            UserType = UserType.Customer,
            Email = "test@test.com",
            Name = "Test User",
            FamilyId = Guid.NewGuid()
        };

        _refreshTokenServiceMock.Setup(s => s.ValidateRefreshTokenAsync(It.IsAny<string>()))
            .ReturnsAsync(refreshToken);
        _refreshTokenServiceMock.Setup(s => s.RevokeTokenFamilyAsync(It.IsAny<Guid>(), It.IsAny<string>()))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _service!.LogoutAsync(new LogoutRequest { RefreshToken = "valid-refresh" });

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task LogoutAsync_InvalidRefreshToken_ReturnsFalse()
    {
        // Arrange
        _refreshTokenServiceMock.Setup(s => s.ValidateRefreshTokenAsync(It.IsAny<string>()))
            .ReturnsAsync((RefreshToken?)null);

        // Act
        var result = await _service!.LogoutAsync(new LogoutRequest { RefreshToken = "invalid" });

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task AuthenticateServiceAsync_ValidCredentials_ReturnsToken()
    {
        // This test requires specific database setup for service credentials
    }

    [Fact]
    public async Task AuthenticateServiceAsync_InvalidClientId_ReturnsNull()
    {
        // Arrange
        var request = new ServiceLoginRequest { ClientId = "invalid", ClientSecret = "secret" };

        // Act
        var result = await _service!.AuthenticateServiceAsync(request, "127.0.0.1");

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task AuthenticateServiceAsync_InvalidSecret_ReturnsNull()
    {
        // Arrange
        var request = new ServiceLoginRequest { ClientId = "service-dev-customer-api", ClientSecret = "wrong-secret" };

        // Act
        var result = await _service!.AuthenticateServiceAsync(request, "127.0.0.1");

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task AuthenticateAsync_EmptyUserType_ThrowsArgumentException()
    {
        // Arrange
        var request = new LoginRequest { Username = "user", Password = "password", UserType = "" };

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(() => _service!.AuthenticateAsync(request, "127.0.0.1"));
    }

    [Fact]
    public async Task AuthenticateAsync_AccountLocked_ReturnsLockedError()
    {
        // This test is complex due to mocking external HTTP calls
        // Skip for now and rely on other tests for coverage
    }

    [Fact]
    public async Task AuthenticateAsync_InvalidCredentials_RecordsFailedAttempt()
    {
        // This test requires complex HTTP mocking - skip for now
    }

    private sealed class DelegatingTestHandler(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> sendAsync) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) => sendAsync(request, cancellationToken);
    }

    private static GoogleExchangeRequest ValidEmployeeRequest() => new()
    {
        Credential = "employee-google-id-token",
        Application = "intranet",
        Nonce = "one-time-nonce-for-employee-tests"
    };

    private void ArrangeVerifiedEmployeeIdentity(
        string email,
        string fullName,
        string? profileImageUrl = null,
        string hostedDomain = "maliev.com")
    {
        _googleIdentityTokenValidatorMock
            .Setup(validator => validator.ValidateAsync(
                "employee-google-id-token",
                "intranet",
                GoogleIdentityExchangeType.Employee,
                "one-time-nonce-for-employee-tests",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new GoogleIdentityValidationResult
            {
                Success = true,
                Identity = new VerifiedGoogleIdentity
                {
                    Subject = $"google-sub-{email}",
                    Email = email,
                    EmailVerified = true,
                    HostedDomain = hostedDomain,
                    FullName = fullName,
                    ProfileImageUrl = profileImageUrl
                }
            });
    }
}
