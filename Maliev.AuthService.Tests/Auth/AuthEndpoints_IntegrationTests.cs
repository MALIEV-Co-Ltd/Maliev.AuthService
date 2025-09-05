using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using Maliev.AuthService.Api.Data;
using Maliev.AuthService.Api.Models;
using Maliev.AuthService.Api.Services;
using Microsoft.AspNetCore.Mvc.Testing;
using Maliev.AuthService.Api;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Moq.Protected;
using Maliev.AuthService.JwtToken;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Maliev.AuthService.JwtToken.Models;

namespace Maliev.AuthService.Tests.Auth
{
    public class AuthEndpoints_IntegrationTests : IClassFixture<WebApplicationFactory<Program>>, IDisposable
    {
        private readonly WebApplicationFactory<Program> _factory;
        private readonly Mock<HttpMessageHandler> _mockHttpMessageHandler;
        
        private static string _inMemoryDatabaseName;

        public AuthEndpoints_IntegrationTests(WebApplicationFactory<Program> factory)
        {
            _mockHttpMessageHandler = new Mock<HttpMessageHandler>();

            // Setup the mock HttpMessageHandler to return OK for any validation endpoint
            _mockHttpMessageHandler.Protected()
                                   .Setup<Task<HttpResponseMessage>>(
                                       "SendAsync",
                                       ItExpr.Is<HttpRequestMessage>(req => 
                                           req.RequestUri.ToString().Contains("http://api.maliev.com/customers/validate") || 
                                           req.RequestUri.ToString().Contains("http://api.maliev.com/employees/validate")),
                                       ItExpr.IsAny<CancellationToken>()
                                   )
                                   .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

            if (string.IsNullOrEmpty(_inMemoryDatabaseName))
            {
                _inMemoryDatabaseName = Guid.NewGuid().ToString();
            }

            _factory = factory.WithWebHostBuilder(builder =>
            {
                builder.ConfigureAppConfiguration((context, config) =>
                {
                    config.AddInMemoryCollection(new Dictionary<string, string>
                    {
                        {"Jwt:SecurityKey", "thisisalongtestkeyforjwtsecurity"},
                        {"Jwt:Issuer", "test.maliev.com"},
                        {"Jwt:Audience", "test.maliev.com"},
                        {"CustomerService:ValidationEndpoint", "http://api.maliev.com/customers/validate"},
                        {"EmployeeService:ValidationEndpoint", "http://api.maliev.com/employees/validate"}
                    });
                });

                builder.ConfigureServices(services =>
                {
                    // Configure the HttpClient for ExternalAuthServiceHttpClient to use the mocked HttpMessageHandler
                    services.AddSingleton<ExternalAuthServiceHttpClient>(sp =>
                    {
                        var httpClient = new HttpClient(_mockHttpMessageHandler.Object);
                        return new ExternalAuthServiceHttpClient(httpClient);
                    });
                });
            });
            Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Testing");
        }

        public void Dispose()
        {
            using (var scope = _factory.Services.CreateScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService<RefreshTokenDbContext>();
                dbContext.Database.EnsureDeleted(); // Clear the in-memory database
            }
        }

        [Fact]
        public async Task PostToken_WithValidUserCredentials_ReturnsOkWithTokenAndRefreshToken()
        {
            // Arrange
            var client = _factory.CreateClient();
            var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes("TestUser:TestPassword"));
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", credentials);

            // Act
            var response = await client.PostAsync("/auth/v1/token", null);

            // Assert
            response.EnsureSuccessStatusCode(); // Status Code 200-299
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var responseContent = await response.Content.ReadAsStringAsync();
            var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseContent, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            Assert.False(string.IsNullOrEmpty(tokenResponse.AccessToken));
            Assert.False(string.IsNullOrEmpty(tokenResponse.RefreshToken));
        }

        [Fact]
        public async Task PostToken_WithValidEmployeeCredentials_ReturnsOkWithTokenAndRefreshToken()
        {
            // Arrange
            var client = _factory.CreateClient();
            var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes("TestEmployee:TestPassword"));
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", credentials);

            // Act
            var response = await client.PostAsync("/auth/v1/token", null);

            // Assert
            response.EnsureSuccessStatusCode(); // Status Code 200-299
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var responseContent = await response.Content.ReadAsStringAsync();
            var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseContent, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            Assert.False(string.IsNullOrEmpty(tokenResponse.AccessToken));
            Assert.False(string.IsNullOrEmpty(tokenResponse.RefreshToken));
        }

        [Fact]
        public async Task PostToken_WithInvalidCredentials_ReturnsUnauthorized()
        {
            // Arrange
            _mockHttpMessageHandler.Protected()
                                   .Setup<Task<HttpResponseMessage>>(
                                       "SendAsync",
                                       ItExpr.Is<HttpRequestMessage>(req => 
                                           req.RequestUri.ToString().Contains("http://api.maliev.com/customers/validate") || 
                                           req.RequestUri.ToString().Contains("http://api.maliev.com/employees/validate")),
                                       ItExpr.IsAny<CancellationToken>()
                                   )
                                   .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.Unauthorized));
            var client = _factory.CreateClient();
            var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes("TestUser:WrongPassword"));
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", credentials);

            // Act
            var response = await client.PostAsync("/auth/v1/token", null);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task PostToken_WithoutAuthorizationHeader_ReturnsBadRequest()
        {
            // Arrange
            var client = _factory.CreateClient();

            // Act
            var response = await client.PostAsync("/auth/v1/token", null);

            // Assert
            if (response.StatusCode != HttpStatusCode.BadRequest)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                Assert.Fail($"Expected BadRequest but got {response.StatusCode}. Content: {errorContent}");
            }
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        [Fact]
        public async Task PostRefreshToken_WithValidRefreshToken_ReturnsOkWithNewTokenAndRefreshToken()
        {
            // Arrange
            var client = _factory.CreateClient();
            var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes("TestUser:TestPassword"));
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", credentials);

            // Generate an initial token with a short expiry to ensure it's expired for the refresh test
            ITokenGenerator tokenGenerator = _factory.Services.GetRequiredService<ITokenGenerator>();
            var initialAccessToken = tokenGenerator.GenerateJwtToken("TestUser", new List<string> { "Customer" }, -1); // expired token
            var initialRefreshTokenString = tokenGenerator.GenerateRefreshTokenString();

            var initialTokenResponse = new TokenResponse
            {
                AccessToken = initialAccessToken,
                RefreshToken = initialRefreshTokenString
            };

            // Save the refresh token to the in-memory database
            using (var scope = _factory.Services.CreateScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService<RefreshTokenDbContext>();
                dbContext.RefreshTokens.Add(new RefreshToken
                {
                    Token = initialTokenResponse.RefreshToken,
                    Expires = DateTime.UtcNow.AddDays(7), // Refresh token valid for 7 days
                    Created = DateTime.UtcNow,
                    Username = "TestUser",
                    CreatedByIp = "127.0.0.1",
                });
                await dbContext.SaveChangesAsync();

                // Verify the refresh token is saved
                var savedToken = await dbContext.RefreshTokens.SingleOrDefaultAsync(rt => rt.Token == initialTokenResponse.RefreshToken);
                Assert.NotNull(savedToken);
            }

            var refreshRequest = new RefreshTokenRequest
            {
                AccessToken = initialTokenResponse.AccessToken,
                RefreshToken = initialTokenResponse.RefreshToken
            };
            var jsonContent = new StringContent(JsonSerializer.Serialize(refreshRequest), Encoding.UTF8, "application/json");

            // Act
            var response = await client.PostAsync("/auth/v1/token/refresh", jsonContent);

            // Assert
            response.EnsureSuccessStatusCode();
            var refreshedTokenResponse = JsonSerializer.Deserialize<TokenResponse>(await response.Content.ReadAsStringAsync(), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            Assert.False(string.IsNullOrEmpty(refreshedTokenResponse.AccessToken));
            Assert.False(string.IsNullOrEmpty(refreshedTokenResponse.RefreshToken));
            Assert.NotEqual(initialTokenResponse.AccessToken, refreshedTokenResponse.AccessToken);
            Assert.NotEqual(initialTokenResponse.RefreshToken, refreshedTokenResponse.RefreshToken);
        }

        [Fact]
        public async Task PostRefreshToken_WithInvalidRefreshToken_ReturnsUnauthorized()
        {
            // Arrange
            var client = _factory.CreateClient();
            var refreshRequest = new RefreshTokenRequest
            {
                AccessToken = "invalid_access_token",
                RefreshToken = "invalid_refresh_token"
            };
            var jsonContent = new StringContent(JsonSerializer.Serialize(refreshRequest), Encoding.UTF8, "application/json");

            // Act
            var response = await client.PostAsync("/auth/v1/token/refresh", jsonContent);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
    [Fact]
        public async Task PostRefreshToken_WithInvalidSignature_ReturnsUnauthorized()
        {
            // Arrange
            var client = _factory.CreateClient();
            var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes("TestUser:TestPassword"));
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", credentials);

            // Generate an initial token with a short expiry to ensure it's expired for the refresh test
            ITokenGenerator tokenGenerator = _factory.Services.GetRequiredService<ITokenGenerator>();
            var initialAccessToken = tokenGenerator.GenerateJwtToken("TestUser", new List<string> { "Customer" }, 1);
            var initialRefreshTokenString = tokenGenerator.GenerateRefreshTokenString();

            var initialTokenResponse = new TokenResponse
            {
                AccessToken = initialAccessToken,
                RefreshToken = initialRefreshTokenString
            };

            // Save the refresh token to the in-memory database
            using (var scope = _factory.Services.CreateScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService<RefreshTokenDbContext>();
                dbContext.RefreshTokens.Add(new RefreshToken
                {
                    Token = initialTokenResponse.RefreshToken,
                    Expires = DateTime.UtcNow.AddDays(7),
                    Created = DateTime.UtcNow,
                    Username = "TestUser",
                    CreatedByIp = "127.0.0.1"
                });
                await dbContext.SaveChangesAsync();

                // Verify the refresh token is saved
                var savedToken = await dbContext.RefreshTokens.SingleOrDefaultAsync(rt => rt.Token == initialTokenResponse.RefreshToken);
                Assert.NotNull(savedToken);
            }

            // Tamper with the token signature
            var tokenParts = initialTokenResponse.AccessToken.Split('.');
            tokenParts[2] = "invalid_signature";
            var tamperedToken = string.Join(".", tokenParts);

            var refreshRequest = new RefreshTokenRequest
            {
                AccessToken = tamperedToken,
                RefreshToken = initialTokenResponse.RefreshToken
            };
            var jsonContent = new StringContent(JsonSerializer.Serialize(refreshRequest), Encoding.UTF8, "application/json");

            // Act
            var response = await client.PostAsync("/auth/v1/token/refresh", jsonContent);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
    }

    // Helper class to deserialize token response
    public class TokenResponse
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }

    // Helper class for refresh token request
    public class RefreshTokenRequest
    {
        public required string AccessToken { get; set; }
        public required string RefreshToken { get; set; }
    }
}