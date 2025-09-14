using Maliev.AuthService.Common.Exceptions;
using Maliev.AuthService.Api.Models;
using Maliev.AuthService.Api.Services;
using Microsoft.Extensions.Logging;
using Moq;
using Moq.Protected;
using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Maliev.AuthService.Tests.Auth
{
    public class ExternalAuthenticationService_UnitTests
    {
        private readonly Mock<ExternalAuthServiceHttpClient> _mockExternalAuthServiceHttpClient;
        private readonly Mock<ILogger<ExternalAuthenticationService>> _mockLogger;
        private readonly ExternalAuthenticationService _service;

        public ExternalAuthenticationService_UnitTests()
        {
            _mockExternalAuthServiceHttpClient = new Mock<ExternalAuthServiceHttpClient>(new HttpClient());
            _mockLogger = new Mock<ILogger<ExternalAuthenticationService>>();

            _service = new ExternalAuthenticationService(
                _mockExternalAuthServiceHttpClient.Object,
                _mockLogger.Object);
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
        public async Task ValidateCredentialsAsync_HttpOK_ReturnsExistsTrueWithDefaultRole()
        {
            // Arrange
            var credentials = new UserValidationRequest { Username = "testuser", Password = "password" };
            var jsonContent = new StringContent(JsonSerializer.Serialize(credentials), Encoding.UTF8, "application/json");
            SetupHttpClientMock(HttpStatusCode.OK);

            // Act
            var result = await _service.ValidateCredentialsAsync("http://customer.service/validate", jsonContent, UserType.Customer);

            // Assert
            Assert.True(result.Exists);
            Assert.Equal("Customer", result.UserType);
            Assert.Contains("Customer", result.Roles);
            Assert.Null(result.Error);
            Assert.Null(result.StatusCode);
        }

        [Fact]
        public async Task ValidateCredentialsAsync_HttpNotFound_ReturnsExistsFalseWithError()
        {
            // Arrange
            var credentials = new UserValidationRequest { Username = "testuser", Password = "password" };
            var jsonContent = new StringContent(JsonSerializer.Serialize(credentials), Encoding.UTF8, "application/json");
            SetupHttpClientMock(HttpStatusCode.NotFound);

            // Act
            var result = await _service.ValidateCredentialsAsync("http://customer.service/validate", jsonContent, UserType.Customer);

            // Assert
            Assert.False(result.Exists);
            Assert.Equal("Customer", result.UserType);
            Assert.Empty(result.Roles);
            Assert.NotNull(result.Error);
            Assert.Contains("User not found", result.Error);
            Assert.Null(result.StatusCode);
        }

        [Fact]
        public async Task ValidateCredentialsAsync_HttpBadRequest_ReturnsExistsFalseWithError()
        {
            // Arrange
            var credentials = new UserValidationRequest { Username = "testuser", Password = "password" };
            var jsonContent = new StringContent(JsonSerializer.Serialize(credentials), Encoding.UTF8, "application/json");
            SetupHttpClientMock(HttpStatusCode.BadRequest);

            // Act
            var result = await _service.ValidateCredentialsAsync("http://customer.service/validate", jsonContent, UserType.Customer);

            // Assert
            Assert.False(result.Exists);
            Assert.Equal("Customer", result.UserType);
            Assert.Empty(result.Roles);
            Assert.NotNull(result.Error);
            Assert.Contains("Invalid credentials", result.Error);
            Assert.Null(result.StatusCode);
        }

        [Fact]
        public async Task ValidateCredentialsAsync_InternalServerError_ReturnsExistsFalseAndError()
        {
            // Arrange
            var credentials = new UserValidationRequest { Username = "testuser", Password = "password" };
            var jsonContent = new StringContent(JsonSerializer.Serialize(credentials), Encoding.UTF8, "application/json");
            SetupHttpClientMock(HttpStatusCode.InternalServerError);

            // Act
            var result = await _service.ValidateCredentialsAsync("http://customer.service/validate", jsonContent, UserType.Customer);

            // Assert
            Assert.False(result.Exists);
            Assert.Equal("Customer", result.UserType);
            Assert.Empty(result.Roles);
            Assert.NotNull(result.Error);
            Assert.Contains("External authentication service returned", result.Error);
            Assert.Equal(500, result.StatusCode);
        }

        [Fact]
        public async Task ValidateCredentialsAsync_HttpRequestException_ThrowsExternalServiceValidationException()
        {
            // Arrange
            var credentials = new UserValidationRequest { Username = "testuser", Password = "password" };
            var jsonContent = new StringContent(JsonSerializer.Serialize(credentials), Encoding.UTF8, "application/json");
            SetupHttpClientMock(HttpStatusCode.OK, null, new HttpRequestException("Network error"));

            // Act & Assert
            await Assert.ThrowsAsync<ExternalServiceValidationException>(() => 
                _service.ValidateCredentialsAsync("http://customer.service/validate", jsonContent, UserType.Customer));
        }

        [Fact]
        public async Task ValidateCredentialsAsync_GeneralException_ThrowsExternalServiceValidationException()
        {
            // Arrange
            var credentials = new UserValidationRequest { Username = "testuser", Password = "password" };
            var jsonContent = new StringContent(JsonSerializer.Serialize(credentials), Encoding.UTF8, "application/json");
            SetupHttpClientMock(HttpStatusCode.OK, null, new Exception("Unexpected error"));

            // Act & Assert
            await Assert.ThrowsAsync<ExternalServiceValidationException>(() => 
                _service.ValidateCredentialsAsync("http://customer.service/validate", jsonContent, UserType.Customer));
        }
    }
}