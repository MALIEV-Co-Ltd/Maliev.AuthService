using Moq;
using Xunit;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Maliev.AuthService.Api.Controllers;
using Maliev.AuthService.Api.Services;
using Maliev.AuthService.Api.Data;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Maliev.AuthService.Api.Models;
using Maliev.AuthService.JwtToken;
using System.Text;
using System.Text.Json;
using System;
using System.Threading;
using Microsoft.EntityFrameworkCore;
using Moq.Protected;

namespace Maliev.AuthService.Tests.Auth
{
    public class ValidateCredentials_UnitTests
    {
        private readonly Mock<ITokenGenerator> _mockTokenGenerator;
        private readonly Mock<ExternalAuthServiceHttpClient> _mockExternalAuthServiceHttpClient;
        private readonly Mock<RefreshTokenDbContext> _mockDbContext;
        private readonly Mock<ILogger<AuthenticationController>> _mockLogger;
        private readonly Mock<IOptions<CustomerServiceOptions>> _mockCustomerServiceOptions;
        private readonly Mock<IOptions<EmployeeServiceOptions>> _mockEmployeeServiceOptions;
        private readonly Mock<IValidationCacheService> _mockValidationCacheService;
        private readonly Mock<ICredentialValidationService> _mockCredentialValidationService;
        private readonly AuthenticationController _controller;

        public ValidateCredentials_UnitTests()
        {
            _mockTokenGenerator = new Mock<ITokenGenerator>();
            _mockExternalAuthServiceHttpClient = new Mock<ExternalAuthServiceHttpClient>(new HttpClient());
            _mockDbContext = new Mock<RefreshTokenDbContext>(new DbContextOptions<RefreshTokenDbContext>());
            _mockLogger = new Mock<ILogger<AuthenticationController>>();
            _mockCustomerServiceOptions = new Mock<IOptions<CustomerServiceOptions>>();
            _mockEmployeeServiceOptions = new Mock<IOptions<EmployeeServiceOptions>>();
            _mockValidationCacheService = new Mock<IValidationCacheService>();
            _mockCredentialValidationService = new Mock<ICredentialValidationService>();

            _mockCustomerServiceOptions.Setup(o => o.Value).Returns(new CustomerServiceOptions { ValidationEndpoint = "http://customer.service/validate" });
            _mockEmployeeServiceOptions.Setup(o => o.Value).Returns(new EmployeeServiceOptions { ValidationEndpoint = "http://employee.service/validate" });
            
            // Setup cache service to return null by default (cache miss)
            _mockValidationCacheService.Setup(c => c.GetValidationResultAsync(It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync((ValidationResult?)null);
                
            // Setup credential validation service to return valid credentials by default
            _mockCredentialValidationService.Setup(c => c.ValidateCredentials(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new CredentialValidationResult { IsValid = true, SanitizedUsername = "testuser", SanitizedPassword = "password" });

            _controller = new AuthenticationController(
                _mockTokenGenerator.Object,
                _mockExternalAuthServiceHttpClient.Object,
                _mockDbContext.Object,
                _mockLogger.Object,
                _mockCustomerServiceOptions.Object,
                _mockEmployeeServiceOptions.Object,
                _mockValidationCacheService.Object,
                _mockCredentialValidationService.Object);
        }

        private void SetupHttpClientMock(HttpStatusCode statusCode, string? content = null, Exception? exception = null)
        {
            var mockHttpMessageHandler = new Mock<HttpMessageHandler>();
            if (exception != null)
            {
                mockHttpMessageHandler.Protected()
                                      .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
                                      .ThrowsAsync(exception);
            }
            else
            {
                var response = new HttpResponseMessage(statusCode);
                if (content != null)
                {
                    response.Content = new StringContent(content, Encoding.UTF8, "application/json");
                }
                mockHttpMessageHandler.Protected()
                                      .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
                                      .ReturnsAsync(response);
            }
            _mockExternalAuthServiceHttpClient.Setup(c => c.Client).Returns(new HttpClient(mockHttpMessageHandler.Object));
        }

        [Fact]
        public async Task ValidateCredentials_SuccessWithRoles_ReturnsExistsTrueAndRoles()
        {
            // Arrange
            var credentials = new { username = "testuser", password = "password" };
            var jsonContent = new StringContent(JsonSerializer.Serialize(credentials), Encoding.UTF8, "application/json");
            var responseContent = "{\"exists\":true,\"roles\":[\"Admin\",\"User\"]}";
            SetupHttpClientMock(HttpStatusCode.OK, responseContent);

            // Act
            var result = await _controller.ValidateCredentials("http://customer.service/validate", jsonContent, "Customer");

            // Assert
            Assert.True(result.Exists);
            Assert.Equal("Customer", result.UserType);
            Assert.Contains("Admin", result.Roles);
            Assert.Contains("User", result.Roles);
            Assert.Null(result.Error);
            Assert.Null(result.StatusCode);
        }

        [Fact]
        public async Task ValidateCredentials_SuccessWithoutRoles_ReturnsExistsTrueAndDefaultRole()
        {
            // Arrange
            var credentials = new { username = "testuser", password = "password" };
            var jsonContent = new StringContent(JsonSerializer.Serialize(credentials), Encoding.UTF8, "application/json");
            var responseContent = "{\"exists\":true}"; // No roles in response
            SetupHttpClientMock(HttpStatusCode.OK, responseContent);

            // Act
            var result = await _controller.ValidateCredentials("http://customer.service/validate", jsonContent, "Customer");

            // Assert
            Assert.True(result.Exists);
            Assert.Equal("Customer", result.UserType);
            Assert.Contains("Customer", result.Roles);
            Assert.Single(result.Roles);
            Assert.Null(result.Error);
            Assert.Null(result.StatusCode);
        }

        [Fact]
        public async Task ValidateCredentials_Unauthorized_ReturnsExistsFalseAndError()
        {
            // Arrange
            var credentials = new { username = "testuser", password = "password" };
            var jsonContent = new StringContent(JsonSerializer.Serialize(credentials), Encoding.UTF8, "application/json");
            SetupHttpClientMock(HttpStatusCode.Unauthorized);

            // Act
            var result = await _controller.ValidateCredentials("http://customer.service/validate", jsonContent, "Customer");

            // Assert
            Assert.False(result.Exists);
            Assert.Equal("Customer", result.UserType);
            Assert.Empty(result.Roles);
            Assert.NotNull(result.Error);
            Assert.Contains("Unauthorized", result.Error);
            Assert.Equal((int)HttpStatusCode.Unauthorized, result.StatusCode);
        }

        [Fact]
        public async Task ValidateCredentials_InternalServerError_ReturnsExistsFalseAndError()
        {
            // Arrange
            var credentials = new { username = "testuser", password = "password" };
            var jsonContent = new StringContent(JsonSerializer.Serialize(credentials), Encoding.UTF8, "application/json");
            SetupHttpClientMock(HttpStatusCode.InternalServerError);

            // Act
            var result = await _controller.ValidateCredentials("http://customer.service/validate", jsonContent, "Customer");

            // Assert
            Assert.False(result.Exists);
            Assert.Equal("Customer", result.UserType);
            Assert.Empty(result.Roles);
            Assert.NotNull(result.Error);
            Assert.Contains("InternalServerError", result.Error);
            Assert.Equal((int)HttpStatusCode.InternalServerError, result.StatusCode);
        }

        [Fact]
        public async Task ValidateCredentials_HttpRequestException_ReturnsExistsFalseAndError()
        {
            // Arrange
            var credentials = new { username = "testuser", password = "password" };
            var jsonContent = new StringContent(JsonSerializer.Serialize(credentials), Encoding.UTF8, "application/json");
            SetupHttpClientMock(HttpStatusCode.OK, exception: new HttpRequestException("Network error"));

            // Act
            var result = await _controller.ValidateCredentials("http://customer.service/validate", jsonContent, "Customer");

            // Assert
            Assert.False(result.Exists);
            Assert.Equal("Customer", result.UserType);
            Assert.Empty(result.Roles);
            Assert.NotNull(result.Error);
            Assert.Contains("HttpRequestException", result.Error);
            Assert.Null(result.StatusCode);
        }

        [Fact]
        public async Task ValidateCredentials_GeneralException_ReturnsExistsFalseAndError()
        {
            // Arrange
            var credentials = new { username = "testuser", password = "password" };
            var jsonContent = new StringContent(JsonSerializer.Serialize(credentials), Encoding.UTF8, "application/json");
            SetupHttpClientMock(HttpStatusCode.OK, exception: new Exception("Generic error"));

            // Act
            var result = await _controller.ValidateCredentials("http://customer.service/validate", jsonContent, "Customer");

            // Assert
            Assert.False(result.Exists);
            Assert.Equal("Customer", result.UserType);
            Assert.Empty(result.Roles);
            Assert.NotNull(result.Error);
            Assert.Contains("An unexpected error occurred", result.Error);
            Assert.Null(result.StatusCode);
        }
    }
}