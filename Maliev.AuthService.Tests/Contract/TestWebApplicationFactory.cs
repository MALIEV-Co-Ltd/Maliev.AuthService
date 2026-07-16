using Maliev.AuthService.Domain.Entities;
using Maliev.AuthService.Application.Identity;
using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Infrastructure.DbContexts;
using Maliev.AuthService.Tests.Infrastructure;
using Maliev.AuthService.Tests.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;

namespace Maliev.AuthService.Tests.Contract;

public class TestWebApplicationFactory : BaseIntegrationTestFactory<Program, AuthDbContext>
{
    private int _iamResolutionCalls;
    private int _legacyIamResolutionCalls;
    private int _tokenIssuanceResolutionCalls;
    private string? _lastTokenIssuanceAuthorization;
    private string? _lastTokenIssuanceRequestBody;

    public static readonly Guid NonexistentIamPrincipalId =
        Guid.Parse("22222222-2222-2222-2222-222222222222");
    public static readonly Guid NullPermissionsIamPrincipalId =
        Guid.Parse("33333333-3333-3333-3333-333333333333");
    public static readonly Guid NullRolesIamPrincipalId =
        Guid.Parse("44444444-4444-4444-4444-444444444444");
    public static readonly Guid NullPermissionElementIamPrincipalId =
        Guid.Parse("55555555-5555-5555-5555-555555555555");
    public static readonly Guid NullRoleElementIamPrincipalId =
        Guid.Parse("66666666-6666-6666-6666-666666666666");
    public static readonly Guid BlankPermissionElementIamPrincipalId =
        Guid.Parse("77777777-7777-7777-7777-777777777777");
    public static readonly Guid BlankRoleElementIamPrincipalId =
        Guid.Parse("88888888-8888-8888-8888-888888888888");
    public static readonly Guid MismatchedIamPrincipalId =
        Guid.Parse("99999999-9999-9999-9999-999999999999");
    public static readonly Guid CachedIamPrincipalId =
        Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    public static readonly Guid ScopedIamPrincipalId =
        Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
    public static readonly Guid ExpiringIamPrincipalId =
        Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc");
    public static readonly Guid MalformedJsonIamPrincipalId =
        Guid.Parse("dddddddd-dddd-dddd-dddd-dddddddddddd");
    public static readonly Guid EmptyResourcePathIamPrincipalId =
        Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff");
    public static readonly Guid SearchServiceIamPrincipalId =
        Guid.Parse("13131313-1313-1313-1313-131313131313");
    public static readonly Guid RegistryServiceIamPrincipalId =
        Guid.Parse("14141414-1414-1414-1414-141414141414");
    public static readonly Guid CountryServiceIamPrincipalId =
        Guid.Parse("15151515-1515-1515-1515-151515151515");

    public int IamResolutionCalls => Volatile.Read(ref _iamResolutionCalls);
    public int LegacyIamResolutionCalls => Volatile.Read(ref _legacyIamResolutionCalls);
    public int TokenIssuanceResolutionCalls => Volatile.Read(ref _tokenIssuanceResolutionCalls);
    public string? LastTokenIssuanceAuthorization => Volatile.Read(ref _lastTokenIssuanceAuthorization);
    public string? LastTokenIssuanceRequestBody => Volatile.Read(ref _lastTokenIssuanceRequestBody);
    /// <summary>
    /// Override CleanDatabaseAsync to seed required test data after cleanup and clear Redis
    /// </summary>
    public new async Task CleanDatabaseAsync()
    {
        Interlocked.Exchange(ref _iamResolutionCalls, 0);
        Interlocked.Exchange(ref _legacyIamResolutionCalls, 0);
        Interlocked.Exchange(ref _tokenIssuanceResolutionCalls, 0);
        Interlocked.Exchange(ref _lastTokenIssuanceAuthorization, null);
        Interlocked.Exchange(ref _lastTokenIssuanceRequestBody, null);
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
        var serviceCredential = new ServiceCredential
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

        context.Set<ServiceCredential>().Add(serviceCredential);
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
        // Set IAM registration delay to 0 for immediate registration in tests
        Environment.SetEnvironmentVariable("IAM__RegistrationDelaySeconds", "0");

        // Set external service URLs via environment variables for testing
        Environment.SetEnvironmentVariable("CustomerService__BaseUrl", "http://localhost:5001");
        Environment.SetEnvironmentVariable("EmployeeService__BaseUrl", "http://localhost:5002");
        Environment.SetEnvironmentVariable("IAMService__BaseUrl", "http://localhost:5100");
        Environment.SetEnvironmentVariable("RateLimiting__ServiceLogin__PeerPermitLimit", "3");
        Environment.SetEnvironmentVariable("RateLimiting__ServiceLogin__ClientPermitLimit", "3");
        Environment.SetEnvironmentVariable("RateLimiting__ServiceLogin__WindowSeconds", "60");

        // Export RSA private and public keys for JWT token generation and validation
        // The base factory provides _testRsa through SigningCredentials property
        var rsa = (SigningCredentials.Key as RsaSecurityKey)?.Rsa;
        if (rsa != null)
        {
            // Export private key for token generation (PKCS#8 format for ImportPkcs8PrivateKey)
            var privateKeyPem = rsa.ExportPkcs8PrivateKeyPem();
            var privateKeyBase64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(privateKeyPem));
            Environment.SetEnvironmentVariable("Jwt__PrivateKey", privateKeyBase64);
            Environment.SetEnvironmentVariable(
                "Auth__TokenIssuanceCapability__ActiveKeyId",
                "auth-capability-test-key");
            Environment.SetEnvironmentVariable(
                "Auth__TokenIssuanceCapability__PrivateKey",
                privateKeyPem);

            // Export public key for token validation
            var publicKeyPem = rsa.ExportSubjectPublicKeyInfoPem();  // Use SubjectPublicKeyInfo format
            var publicKeyBase64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(publicKeyPem));
            Environment.SetEnvironmentVariable("Jwt__PublicKey", publicKeyBase64);
        }
    }

    protected override void ConfigureAdditionalServices(IServiceCollection services)
    {
        services.RemoveAll<StackExchange.Redis.IConnectionMultiplexer>();
        services.AddSingleton<StackExchange.Redis.IConnectionMultiplexer>(_ =>
        {
            var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__redis")
                ?? throw new InvalidOperationException("The Redis Testcontainer connection is unavailable");
            return StackExchange.Redis.ConnectionMultiplexer.Connect(connectionString);
        });

        services.RemoveAll<IGoogleIdentityTokenValidator>();
        services.AddSingleton<IGoogleIdentityTokenValidator, TestGoogleIdentityTokenValidator>();

        // Remove existing HttpClient registration
        var httpClientDescriptor = services.FirstOrDefault(d => d.ServiceType == typeof(IHttpClientFactory));
        if (httpClientDescriptor != null)
        {
            services.Remove(httpClientDescriptor);
        }

        // Add mock HTTP client factory that returns successful validation responses
        services.AddSingleton<IHttpClientFactory>(sp => new MockHttpClientFactory(
            sp.GetRequiredService<IConfiguration>(),
            this));
    }

    private sealed class TestGoogleIdentityTokenValidator : IGoogleIdentityTokenValidator
    {
        public Task<GoogleIdentityValidationResult> ValidateAsync(
            string credential,
            string application,
            GoogleIdentityExchangeType exchangeType,
            string expectedNonce,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(credential) || string.IsNullOrWhiteSpace(application))
            {
                return Task.FromResult(new GoogleIdentityValidationResult
                {
                    Success = false,
                    ErrorCode = "invalid_google_credential",
                    ErrorDescription = "Google credential is invalid or expired"
                });
            }

            var email = credential.Trim();
            var hostedDomain = email.EndsWith("@maliev.com", StringComparison.OrdinalIgnoreCase)
                ? "maliev.com"
                : null;
            var name = email.Split('@', 2)[0].Replace('.', ' ');

            return Task.FromResult(new GoogleIdentityValidationResult
            {
                Success = true,
                Identity = new VerifiedGoogleIdentity
                {
                    Subject = $"test-google-sub-{email}",
                    Email = email,
                    EmailVerified = true,
                    HostedDomain = hostedDomain,
                    FullName = name,
                    ProfileImageUrl = $"https://lh3.googleusercontent.com/a/{Uri.EscapeDataString(email)}"
                }
            });
        }
    }

    private class MockHttpClientFactory : IHttpClientFactory
    {
        private readonly IConfiguration _configuration;
        private readonly TestWebApplicationFactory _owner;

        public MockHttpClientFactory(
            IConfiguration configuration,
            TestWebApplicationFactory owner)
        {
            _configuration = configuration;
            _owner = owner;
        }

        public HttpClient CreateClient(string name)
        {
            var handler = new MockHttpMessageHandler(_owner);
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
        private readonly TestWebApplicationFactory _owner;

        public MockHttpMessageHandler(TestWebApplicationFactory owner)
        {
            _owner = owner;
        }

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
                    if (jsonDoc.RootElement.TryGetProperty("email", out var emailElement))
                        username = emailElement.GetString();
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
                    var userId = Guid.NewGuid();
                    var principalId = Guid.NewGuid();
                    var response = new
                    {
                        is_valid = true,
                        user_id = userId,
                        customer_id = username.EndsWith("@maliev.com", StringComparison.OrdinalIgnoreCase) ? (Guid?)null : userId,
                        principal_id = principalId,
                        email = username,
                        name = "Test User",
                        display_name = "Test User"
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
                    is_valid = false,
                    user_id = generatedUserId,
                    error = "Invalid credentials"
                };


                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(invalidResponse)
                };
            }

            // Mock IAM resolution response
            if (request.RequestUri?.PathAndQuery.Contains("/iam/v1/auth/token-issuance/resolve-permissions") == true)
            {
                Interlocked.Increment(ref _owner._iamResolutionCalls);
                Interlocked.Increment(ref _owner._tokenIssuanceResolutionCalls);
                Interlocked.Exchange(
                    ref _owner._lastTokenIssuanceAuthorization,
                    request.Headers.Authorization?.Parameter);
                if (request.RequestUri.Port == 5101)
                {
                    return new HttpResponseMessage(HttpStatusCode.InternalServerError);
                }

                string? principalId = null;
                if (request.Content != null)
                {
                    var requestBody = await request.Content.ReadAsStringAsync(cancellationToken);
                    Interlocked.Exchange(ref _owner._lastTokenIssuanceRequestBody, requestBody);
                    var jsonDoc = JsonDocument.Parse(requestBody);
                    if (jsonDoc.RootElement.TryGetProperty("PrincipalId", out var principalIdElement) ||
                        jsonDoc.RootElement.TryGetProperty("principalId", out principalIdElement))
                        principalId = principalIdElement.GetString();
                }

                if (string.Equals(
                    principalId,
                    NonexistentIamPrincipalId.ToString(),
                    StringComparison.OrdinalIgnoreCase))
                {
                    return new HttpResponseMessage(HttpStatusCode.NotFound);
                }

                var malformedAuthorityJson = principalId switch
                {
                    var value when string.Equals(value, NullPermissionsIamPrincipalId.ToString(), StringComparison.OrdinalIgnoreCase) =>
                        $$"""{"principalId":"{{principalId}}","permissions":null,"roles":[],"resourcePath":null,"cacheUntil":null,"fromCache":false}""",
                    var value when string.Equals(value, NullRolesIamPrincipalId.ToString(), StringComparison.OrdinalIgnoreCase) =>
                        $$"""{"principalId":"{{principalId}}","permissions":[],"roles":null,"resourcePath":null,"cacheUntil":null,"fromCache":false}""",
                    var value when string.Equals(value, NullPermissionElementIamPrincipalId.ToString(), StringComparison.OrdinalIgnoreCase) =>
                        $$"""{"principalId":"{{principalId}}","permissions":[null],"roles":[],"resourcePath":null,"cacheUntil":null,"fromCache":false}""",
                    var value when string.Equals(value, NullRoleElementIamPrincipalId.ToString(), StringComparison.OrdinalIgnoreCase) =>
                        $$"""{"principalId":"{{principalId}}","permissions":[],"roles":[null],"resourcePath":null,"cacheUntil":null,"fromCache":false}""",
                    var value when string.Equals(value, BlankPermissionElementIamPrincipalId.ToString(), StringComparison.OrdinalIgnoreCase) =>
                        $$"""{"principalId":"{{principalId}}","permissions":["   "],"roles":[],"resourcePath":null,"cacheUntil":null,"fromCache":false}""",
                    var value when string.Equals(value, BlankRoleElementIamPrincipalId.ToString(), StringComparison.OrdinalIgnoreCase) =>
                        $$"""{"principalId":"{{principalId}}","permissions":[],"roles":[""],"resourcePath":null,"cacheUntil":null,"fromCache":false}""",
                    var value when string.Equals(value, MismatchedIamPrincipalId.ToString(), StringComparison.OrdinalIgnoreCase) =>
                        """{"principalId":"eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee","permissions":[],"roles":[],"resourcePath":null,"cacheUntil":null,"fromCache":false}""",
                    var value when string.Equals(value, CachedIamPrincipalId.ToString(), StringComparison.OrdinalIgnoreCase) =>
                        $$"""{"principalId":"{{principalId}}","permissions":[],"roles":[],"resourcePath":null,"cacheUntil":null,"fromCache":true}""",
                    var value when string.Equals(value, ScopedIamPrincipalId.ToString(), StringComparison.OrdinalIgnoreCase) =>
                        $$"""{"principalId":"{{principalId}}","permissions":[],"roles":[],"resourcePath":"projects/project-1","cacheUntil":null,"fromCache":false}""",
                    var value when string.Equals(value, ExpiringIamPrincipalId.ToString(), StringComparison.OrdinalIgnoreCase) =>
                        $$"""{"principalId":"{{principalId}}","permissions":[],"roles":[],"resourcePath":null,"cacheUntil":"2026-07-16T04:05:00Z","fromCache":false}""",
                    var value when string.Equals(value, MalformedJsonIamPrincipalId.ToString(), StringComparison.OrdinalIgnoreCase) =>
                        "{not-json",
                    var value when string.Equals(value, EmptyResourcePathIamPrincipalId.ToString(), StringComparison.OrdinalIgnoreCase) =>
                        $$"""{"principalId":"{{principalId}}","permissions":[],"roles":[],"resourcePath":"","cacheUntil":null,"fromCache":false}""",
                    _ => null
                };
                if (malformedAuthorityJson is not null)
                {
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(malformedAuthorityJson)
                    };
                }

                if (string.Equals(
                    principalId,
                    SearchServiceIamPrincipalId.ToString(),
                    StringComparison.OrdinalIgnoreCase))
                {
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(
                            $$"""
                            {
                              "principalId": "{{principalId}}",
                              "permissions": ["iam.auth.check-permission"],
                              "roles": ["roles.workloads.search-service.v1"],
                              "resourcePath": null,
                              "cacheUntil": null,
                              "fromCache": false
                            }
                            """)
                    };
                }

                if (string.Equals(
                    principalId,
                    RegistryServiceIamPrincipalId.ToString(),
                    StringComparison.OrdinalIgnoreCase))
                {
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(
                            $$"""
                            {
                              "principalId": "{{principalId}}",
                              "permissions": ["iam.auth.check-permission"],
                              "roles": ["roles.workloads.registry-service.v1"],
                              "resourcePath": null,
                              "cacheUntil": null,
                              "fromCache": false
                            }
                            """)
                    };
                }

                if (string.Equals(
                    principalId,
                    CountryServiceIamPrincipalId.ToString(),
                    StringComparison.OrdinalIgnoreCase))
                {
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(
                            $$"""
                            {
                              "principalId": "{{principalId}}",
                              "permissions": ["iam.auth.check-permission"],
                              "roles": ["roles.workloads.country-service.v1"],
                              "resourcePath": null,
                              "cacheUntil": null,
                              "fromCache": false
                            }
                            """)
                    };
                }

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        $$"""
                        {
                          "principalId": "{{principalId ?? Guid.NewGuid().ToString()}}",
                          "permissions": ["auth.api_keys.manage", "auth.users.read"],
                          "roles": ["security_admin"],
                          "resourcePath": null,
                          "cacheUntil": null,
                          "fromCache": false
                        }
                        """)
                };
            }

            if (request.RequestUri?.PathAndQuery.Contains("/iam/v1/auth/resolve-permissions") == true)
            {
                Interlocked.Increment(ref _owner._iamResolutionCalls);
                Interlocked.Increment(ref _owner._legacyIamResolutionCalls);
                if (request.RequestUri.Port == 5101)
                {
                    return new HttpResponseMessage(HttpStatusCode.InternalServerError);
                }

                string? principalId = null;
                if (request.Content != null)
                {
                    var requestBody = await request.Content.ReadAsStringAsync(cancellationToken);
                    var jsonDoc = JsonDocument.Parse(requestBody);
                    if (jsonDoc.RootElement.TryGetProperty("PrincipalId", out var principalIdElement) ||
                        jsonDoc.RootElement.TryGetProperty("principalId", out principalIdElement))
                        principalId = principalIdElement.GetString();
                }

                if (string.Equals(
                    principalId,
                    NonexistentIamPrincipalId.ToString(),
                    StringComparison.OrdinalIgnoreCase))
                {
                    return new HttpResponseMessage(HttpStatusCode.NotFound);
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

            // Mock CustomerService customer Google link/register endpoint
            if (request.RequestUri?.PathAndQuery.Contains("/customer/v1/customers/google/link-or-register") == true)
            {
                string? email = null;
                string? firstName = null;
                string? lastName = null;

                if (request.Content != null)
                {
                    var requestBody = await request.Content.ReadAsStringAsync(cancellationToken);
                    var jsonDoc = JsonDocument.Parse(requestBody);
                    if (jsonDoc.RootElement.TryGetProperty("email", out var emailElement))
                        email = emailElement.GetString();
                    if (jsonDoc.RootElement.TryGetProperty("firstName", out var firstNameElement))
                        firstName = firstNameElement.GetString();
                    if (jsonDoc.RootElement.TryGetProperty("lastName", out var lastNameElement))
                        lastName = lastNameElement.GetString();
                }

                var response = new
                {
                    customerId = Guid.NewGuid(),
                    principalId = Guid.NewGuid(),
                    email = email ?? "customer@gmail.com",
                    displayName = $"{firstName} {lastName}".Trim(),
                    preferredLanguage = "th"
                };

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(response)
                };
            }

            // Mock CustomerService password reset endpoints
            if (request.RequestUri?.PathAndQuery.Contains("/customer/v1/customers/password-reset/request") == true)
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(new { accepted = true, resetToken = "reset-token" })
                };
            }

            if (request.RequestUri?.PathAndQuery.Contains("/customer/v1/customers/password-reset/confirm") == true)
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(new { accepted = true, customerId = Guid.NewGuid() })
                };
            }

            // Mock EmployeeService by-email endpoint
            if (request.RequestUri?.PathAndQuery.Contains("/employee/v1/employees/by-email/") == true)
            {
                var email = Uri.UnescapeDataString(request.RequestUri.Segments.Last());

                if (email == "service.down@maliev.com")
                {
                    return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
                }

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

                if (email == "provision.fail@maliev.com")
                {
                    return new HttpResponseMessage(HttpStatusCode.InternalServerError);
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
