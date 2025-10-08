using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Maliev.AuthService.Data.DbContexts;
using System.Net;
using System.Text.Json;
using System.Net.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;

namespace Maliev.AuthService.Tests.Contract;

public class TestWebApplicationFactory : WebApplicationFactory<Program>
{
    private readonly string _databaseName = $"TestDb_{Guid.NewGuid()}";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            // Remove ALL existing DbContext registrations
            var descriptorsToRemove = services.Where(d =>
                d.ServiceType == typeof(DbContextOptions<AuthDbContext>) ||
                d.ServiceType == typeof(DbContextOptions) ||
                d.ImplementationType?.Name.Contains("AuthDbContext") == true ||
                d.ServiceType == typeof(AuthDbContext)).ToList();

            foreach (var descriptor in descriptorsToRemove)
            {
                services.Remove(descriptor);
            }

            // Add in-memory database for testing
            // Use a unique database name per factory instance for test isolation
            services.AddDbContext<AuthDbContext>(options =>
            {
                options.UseInMemoryDatabase(_databaseName);
            });

            // Remove ALL existing HttpClient-related registrations
            var httpDescriptors = services.Where(d =>
                d.ServiceType == typeof(IHttpClientFactory) ||
                d.ServiceType == typeof(HttpClient) ||
                d.ServiceType.FullName?.Contains("HttpClient") == true ||
                d.ImplementationType?.FullName?.Contains("HttpClient") == true).ToList();

            foreach (var descriptor in httpDescriptors)
            {
                services.Remove(descriptor);
            }

            // Add mock HttpClient factory - must be FIRST before any other HTTP registrations
            services.AddSingleton<IHttpClientFactory, MockHttpClientFactory>();

            // Ensure HttpClient itself uses our factory
            services.AddTransient(sp =>
            {
                var factory = sp.GetRequiredService<IHttpClientFactory>();
                return factory.CreateClient();
            });

            // Build the service provider
            var sp = services.BuildServiceProvider();

            // Create a scope to obtain a reference to the database context
            using (var scope = sp.CreateScope())
            {
                var scopedServices = scope.ServiceProvider;
                var db = scopedServices.GetRequiredService<AuthDbContext>();

                // Ensure the database is created
                db.Database.EnsureCreated();

                // Seed test service credential
                // Secret: "valid_service_secret" -> SHA256 hash
                var testServiceCredential = new Maliev.AuthService.Data.Entities.ServiceCredential
                {
                    Id = Guid.NewGuid(),
                    ClientId = "service-dev-customer-api",
                    ClientSecretHash = "536cd80fe9c61705de47dacb3fc7c4d3c4c331841afe942a9966abc5e4ad70ef", // SHA256("valid_service_secret")
                    ServiceName = "Customer API",
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };

                db.ServiceCredentials.Add(testServiceCredential);
                db.SaveChanges();
            }
        });

        builder.UseEnvironment("Testing");
    }
}

public class MockHttpClientFactory : IHttpClientFactory
{
    public HttpClient CreateClient(string name)
    {
        var handler = new MockHttpMessageHandler();
        return new HttpClient(handler);
    }
}

public class MockHttpMessageHandler : HttpMessageHandler
{
    private static Guid GenerateConsistentUserId(string? username)
    {
        if (string.IsNullOrEmpty(username))
            return Guid.NewGuid();

        // Generate a consistent GUID from the username using a simple hash
        using var md5 = System.Security.Cryptography.MD5.Create();
        var hash = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(username));
        return new Guid(hash);
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Mock credential validation
        if (request.RequestUri?.PathAndQuery.Contains("/validate") == true)
        {
            // Read the request body to check credentials
            var requestBody = await request.Content!.ReadAsStringAsync(cancellationToken);
            using var doc = JsonDocument.Parse(requestBody);
            var username = doc.RootElement.GetProperty("username").GetString();
            var password = doc.RootElement.GetProperty("password").GetString();

            // Determine if credentials are valid
            // Invalid: "invalid@example.com", "locked@example.com", "ratelimit@example.com" with wrong password
            // Valid: anything with "ValidPassword123!"
            var isValid = password == "ValidPassword123!" || password == "Password123!";

            // Use consistent UserId per username for lockout tracking
            var userId = GenerateConsistentUserId(username);

            object response;
            if (isValid)
            {
                response = new
                {
                    IsValid = true,
                    UserId = userId,
                    Email = username,
                    Name = "Test User"
                };
            }
            else
            {
                response = new
                {
                    IsValid = false,
                    UserId = userId,  // Include UserId even for failed attempts to enable lockout tracking
                    Email = (string?)null,
                    Name = (string?)null
                };
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(response), System.Text.Encoding.UTF8, "application/json")
            };
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }
}
