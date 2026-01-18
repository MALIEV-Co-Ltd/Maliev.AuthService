using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Tests.Infrastructure;
using Maliev.AuthService.Tests.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;

namespace Maliev.AuthService.Tests.Contract;

public class TestWebApplicationFactory : BaseIntegrationTestFactory<Program, AuthDbContext>
{
    /// <summary>
    /// Override CleanDatabaseAsync to seed required test data after cleanup and clear Redis
    /// </summary>
    public new async Task CleanDatabaseAsync()
    {
        await base.CleanDatabaseAsync();
        await ClearRedisAsync();
        await SeedTestDataAsync();
    }

    /// <summary>
    /// Clears all Redis keys to ensure clean state between tests
    /// </summary>
    private async Task ClearRedisAsync()
    {
        var redisConnectionString = Environment.GetEnvironmentVariable("ConnectionStrings__redis");
        if (!string.IsNullOrEmpty(redisConnectionString))
        {
            // Add allowAdmin=true to enable FLUSHALL command
            var connectionString = $"{redisConnectionString},allowAdmin=true";
            await using var connection = await StackExchange.Redis.ConnectionMultiplexer.ConnectAsync(connectionString);
            var server = connection.GetServer(connection.GetEndPoints().First());
            await server.FlushAllDatabasesAsync();
        }
    }

    /// <summary>
    /// Seeds required test data for AuthService tests
    /// </summary>
    private async Task SeedTestDataAsync()
    {
        await using var context = GetDbContext();

        // Seed service credentials for service login tests
        var serviceCredential = new Maliev.AuthService.Data.Entities.ServiceCredential
        {
            Id = Guid.NewGuid(),
            ClientId = "service-dev-customer-api",
            PrincipalId = Guid.Parse("11111111-1111-1111-1111-111111111111"), // Test principal ID for IAM integration
            ClientSecretHash = ComputeSha256Hash(TestConstants.DummyValidServiceSecret),
            ServiceName = "Customer API Service",
            IsActive = true,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        context.Set<Maliev.AuthService.Data.Entities.ServiceCredential>().Add(serviceCredential);
        await context.SaveChangesAsync();
    }

    /// <summary>
    /// Computes SHA-256 hash of a string
    /// </summary>
    private static string ComputeSha256Hash(string input)
    {
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var bytes = System.Text.Encoding.UTF8.GetBytes(input);
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    protected override void ConfigureEnvironmentVariables()
    {
        // Set external service URLs via environment variables for testing
        Environment.SetEnvironmentVariable("CustomerService__BaseUrl", "http://localhost:5001");
        Environment.SetEnvironmentVariable("EmployeeService__BaseUrl", "http://localhost:5002");
        Environment.SetEnvironmentVariable("IAMService__BaseUrl", "http://localhost:5100");

        // Export RSA private and public keys for JWT token generation and validation
        // The base factory provides _testRsa through SigningCredentials property
        var rsa = (SigningCredentials.Key as RsaSecurityKey)?.Rsa;
        if (rsa != null)
        {
            // Export private key for token generation (PKCS#8 format for ImportPkcs8PrivateKey)
            var privateKeyPem = rsa.ExportPkcs8PrivateKeyPem();
            var privateKeyBase64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(privateKeyPem));
            Environment.SetEnvironmentVariable("Jwt__PrivateKey", privateKeyBase64);

            // Export public key for token validation
            var publicKeyPem = rsa.ExportSubjectPublicKeyInfoPem();  // Use SubjectPublicKeyInfo format
            var publicKeyBase64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(publicKeyPem));
            Environment.SetEnvironmentVariable("Jwt__PublicKey", publicKeyBase64);
        }
    }

    protected override void ConfigureAdditionalServices(IServiceCollection services)
    {
        // Remove existing HttpClient registration
        var httpClientDescriptor = services.FirstOrDefault(d => d.ServiceType == typeof(IHttpClientFactory));
        if (httpClientDescriptor != null)
        {
            services.Remove(httpClientDescriptor);
        }

        // Add mock HTTP client factory that returns successful validation responses
        services.AddSingleton<IHttpClientFactory>(sp => new MockHttpClientFactory(sp.GetRequiredService<IConfiguration>()));
    }

    private class MockHttpClientFactory : IHttpClientFactory
    {
        private readonly IConfiguration _configuration;

        public MockHttpClientFactory(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public HttpClient CreateClient(string name)
        {
            var handler = new MockHttpMessageHandler();
            var client = new HttpClient(handler);

            // Try to get BaseAddress from configuration, default to localhost if not found
            var iamBaseUrl = _configuration["IAMService:BaseUrl"];
            if (!string.IsNullOrEmpty(iamBaseUrl))
            {
                client.BaseAddress = new Uri(iamBaseUrl);
            }
            else
            {
                client.BaseAddress = new Uri("http://localhost");
            }

            return client;
        }
    }

    private class MockHttpMessageHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Mock external service validation responses
            if (request.RequestUri?.PathAndQuery.Contains("/validate") == true)
            {
                string? username = null;
                string? password = null;

                if (request.Content != null)
                {
                    var requestBody = await request.Content.ReadAsStringAsync(cancellationToken);
                    var jsonDoc = JsonDocument.Parse(requestBody);

                    if (jsonDoc.RootElement.TryGetProperty("username", out var usernameElement))
                        username = usernameElement.GetString();
                    if (jsonDoc.RootElement.TryGetProperty("password", out var passwordElement))
                        password = passwordElement.GetString();
                }

                var validUsers = new Dictionary<string, string>
                {
                    { "customer@example.com", TestConstants.DummyPassword },
                    { "employee@maliev.com", TestConstants.DummyPassword }
                };

                if (username != null && validUsers.TryGetValue(username, out var expectedPassword) && password == expectedPassword)
                {
                    var response = new
                    {
                        IsValid = true,
                        UserId = Guid.NewGuid(),
                        PrincipalId = Guid.NewGuid(),
                        Email = username,
                        Name = "Test User"
                    };

                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = JsonContent.Create(response)
                    };
                }

                Guid generatedUserId;
                if (!string.IsNullOrEmpty(username))
                {
                    using var sha256 = System.Security.Cryptography.SHA256.Create();
                    var hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(username));
                    var guidBytes = new byte[16];
                    Array.Copy(hashBytes, guidBytes, 16);
                    generatedUserId = new Guid(guidBytes);
                }
                else
                {
                    generatedUserId = Guid.NewGuid();
                }

                var invalidResponse = new
                {
                    IsValid = false,
                    UserId = generatedUserId,
                    Error = "Invalid credentials"
                };

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(invalidResponse)
                };
            }

            // Mock IAM resolution response
            if (request.RequestUri?.PathAndQuery.Contains("/iam/v1/auth/resolve-permissions") == true)
            {
                if (request.RequestUri.Port == 5101)
                {
                    return new HttpResponseMessage(HttpStatusCode.InternalServerError);
                }

                string? principalId = null;
                if (request.Content != null)
                {
                    var requestBody = await request.Content.ReadAsStringAsync(cancellationToken);
                    var jsonDoc = JsonDocument.Parse(requestBody);
                    if (jsonDoc.RootElement.TryGetProperty("principalId", out var principalIdElement))
                        principalId = principalIdElement.GetString();
                }

                var response = new
                {
                    principalId = principalId ?? Guid.NewGuid().ToString(),
                    permissions = new[] { "auth.api_keys.manage", "auth.users.read" },
                    roles = new[] { "security_admin" },
                    resolvedAt = DateTime.UtcNow
                };

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(response)
                };
            }

            // Mock EmployeeService by-email endpoint
            if (request.RequestUri?.PathAndQuery.Contains("/employee/v1/employees/by-email/") == true)
            {
                var email = Uri.UnescapeDataString(request.RequestUri.Segments.Last());

                if (email == "existing.employee@maliev.com")
                {
                    var response = new
                    {
                        employeeId = Guid.NewGuid(),
                        principalId = Guid.Parse("7c9e6639-7420-4007-8596-f0ad96130444"),
                        email = email,
                        fullName = "Existing Employee",
                        employmentStatus = "Active"
                    };

                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = JsonContent.Create(response)
                    };
                }

                if (email == "terminated.employee@maliev.com")
                {
                    var response = new
                    {
                        employeeId = Guid.NewGuid(),
                        principalId = Guid.NewGuid(),
                        email = email,
                        fullName = "Terminated Employee",
                        employmentStatus = "Terminated"
                    };

                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = JsonContent.Create(response)
                    };
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            }

            // Mock EmployeeService auto-provision endpoint
            if (request.RequestUri?.PathAndQuery.Contains("/employee/v1/employees/auto-provision") == true)
            {
                string? email = null;
                string? fullName = null;

                if (request.Content != null)
                {
                    var requestBody = await request.Content.ReadAsStringAsync(cancellationToken);
                    var jsonDoc = JsonDocument.Parse(requestBody);
                    if (jsonDoc.RootElement.TryGetProperty("email", out var emailElement))
                        email = emailElement.GetString();
                    if (jsonDoc.RootElement.TryGetProperty("full_name", out var fullNameElement))
                        fullName = fullNameElement.GetString();
                }

                var response = new
                {
                    employeeId = Guid.NewGuid(),
                    principalId = Guid.NewGuid(),
                    email = email,
                    fullName = fullName ?? "New Employee",
                    employeeNumber = "EMP-TEST-001",
                    employmentStatus = "Active"
                };

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(response)
                };
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }
    }
}
