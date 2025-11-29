using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Tests.Infrastructure;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Maliev.AuthService.Tests.Contract;

public class TestWebApplicationFactory : WebApplicationFactory<Program>
{
    // Each factory instance gets its own database fixture for complete isolation
    private readonly TestDatabaseFixture _databaseFixture;
    // Shared RSA keys across all tests to ensure token compatibility
    private static readonly (string PublicKey, string PrivateKey) _sharedKeys = GenerateRsaKeyPair();

    public TestWebApplicationFactory()
    {
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Testing");
        
        // Create a unique database fixture for THIS test instance
        _databaseFixture = new TestDatabaseFixture();
        _databaseFixture.InitializeAsync().GetAwaiter().GetResult();
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            // Remove existing DbContext registrations
            var descriptorsToRemove = services.Where(d =>
                d.ServiceType == typeof(DbContextOptions<AuthDbContext>) ||
                d.ServiceType == typeof(DbContextOptions) ||
                d.ImplementationType?.Name.Contains("AuthDbContext") == true ||
                d.ServiceType == typeof(AuthDbContext)).ToList();

            foreach (var descriptor in descriptorsToRemove)
            {
                services.Remove(descriptor);
            }

            // Add PostgreSQL test database with THIS instance's connection string
            services.AddDbContext<AuthDbContext>(options =>
            {
                options.UseNpgsql(_databaseFixture.ConnectionString);
            });

            // Replace HTTP client with mock handler for all external service calls
            var httpClientFactoryDescriptors = services
                .Where(d => d.ServiceType == typeof(IHttpMessageHandlerFactory) ||
                           d.ServiceType == typeof(IHttpClientFactory) ||
                           d.ImplementationType?.Name.Contains("HttpClient") == true)
                .ToList();

            foreach (var descriptor in httpClientFactoryDescriptors)
            {
                services.Remove(descriptor);
            }

            // Add a single mock HTTP client that handles all requests
            services.AddHttpClient(Options.DefaultName)
                .ConfigurePrimaryHttpMessageHandler(() => new SmartMockHttpMessageHandler());
        });

        builder.ConfigureAppConfiguration((context, config) =>
        {
            // Use SHARED RSA keys so tokens created in one part of test can be validated in another
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                { "Jwt:PublicKey", _sharedKeys.PublicKey },
                { "Jwt:PrivateKey", _sharedKeys.PrivateKey },
                { "Jwt:Issuer", "https://auth.test.local" },
                { "Jwt:Audience", "https://api.test.local" },
                { "ExternalServices:CustomerService:BaseUrl", "http://mock-customer-service" },
                { "ExternalServices:CustomerService:ValidationEndpoint", "/validate" },
                { "ExternalServices:CustomerService:TimeoutInSeconds", "30" },
                { "ExternalServices:EmployeeService:BaseUrl", "http://mock-employee-service" },
                { "ExternalServices:EmployeeService:ValidationEndpoint", "/validate" },
                { "ExternalServices:EmployeeService:TimeoutInSeconds", "30" }
            });
        });

        builder.UseEnvironment("Testing");
    }

    /// <summary>
    /// Generates a new RSA key pair for testing (2048-bit)
    /// </summary>
    /// <returns>Tuple of (Base64-encoded public key PEM, Base64-encoded private key PEM)</returns>
    private static (string PublicKeyPem, string PrivateKeyPem) GenerateRsaKeyPair()
    {
        using var rsa = RSA.Create(2048);
        
        // Export keys to PEM format
        var publicKeyPem = rsa.ExportRSAPublicKeyPem();
        var privateKeyPem = rsa.ExportRSAPrivateKeyPem();
        
        // Convert to Base64 for configuration (matching production format)
        var publicKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(publicKeyPem));
        var privateKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(privateKeyPem));
        
        return (publicKeyBase64, privateKeyBase64);
    }

    public async Task ResetDatabaseAsync()
    {
        await _databaseFixture.ClearDatabaseAsync();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _databaseFixture?.Dispose();
        }
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        _databaseFixture?.Dispose();
        await base.DisposeAsync();
    }
}

/// <summary>
/// Mock HTTP message handler for testing external service calls.
/// Intelligently routes requests to mock responses based on URL patterns.
/// </summary>
public class SmartMockHttpMessageHandler : HttpMessageHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var url = request.RequestUri?.ToString() ?? string.Empty;
        
        // Read request body to check credentials
        string requestBody = "";
        if (request.Content != null)
        {
            requestBody = await request.Content.ReadAsStringAsync(cancellationToken);
        }
        
        // Check if this is a customer service validation request
        if (url.Contains("/validate") && (url.Contains("customer") || url.Contains("5001")))
        {
            var (userId, username) = GetDeterministicUser(requestBody);
            
            // Simple check for "Wrong" or "Invalid" in the password field within the JSON body
            bool isInvalidPassword = requestBody.Contains("Wrong") || requestBody.Contains("Invalid");
            
            var response = new
            {
                isValid = !isInvalidPassword,
                userId = userId,
                email = username,
                name = $"Test {username}"
            };
            
            var jsonResponse = JsonSerializer.Serialize(response, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
            
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(jsonResponse, Encoding.UTF8, "application/json")
            };
        }
        
        // Check if this is an employee service validation request
        if (url.Contains("/validate") && (url.Contains("employee") || url.Contains("5002")))
        {
            var (userId, username) = GetDeterministicUser(requestBody);

            bool isInvalidPassword = requestBody.Contains("Wrong") || requestBody.Contains("Invalid");

            var response = new
            {
                isValid = !isInvalidPassword,
                userId = userId,
                email = username,
                name = $"Test {username}"
            };
            
            var jsonResponse = JsonSerializer.Serialize(response, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
            
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(jsonResponse, Encoding.UTF8, "application/json")
            };
        }
        
        // Default 404 response for unmocked paths
        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private (Guid UserId, string Username) GetDeterministicUser(string jsonBody)
    {
        try
        {
            using var doc = JsonDocument.Parse(jsonBody);
            if (doc.RootElement.TryGetProperty("username", out var usernameProp))
            {
                var username = usernameProp.GetString() ?? "unknown";
                var hash = MD5.HashData(Encoding.UTF8.GetBytes(username));
                return (new Guid(hash), username);
            }
        }
        catch
        {
            // Ignore parsing errors
        }
        
        return (Guid.NewGuid(), "unknown");
    }
}
