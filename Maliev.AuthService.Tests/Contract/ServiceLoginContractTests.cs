using System.Net;
using System.Net.Http.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Maliev.AuthService.Domain.Entities;
using Maliev.AuthService.Tests.Infrastructure;
using Xunit;

namespace Maliev.AuthService.Tests.Contract;

[Collection("AuthService Collection")]
public class ServiceLoginContractTests : IntegrationTestBase
{
    public ServiceLoginContractTests(TestWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_ValidCredentials_Returns200WithServiceToken()
    {
        await CleanDatabaseAsync();
        // Arrange
        var request = new
        {
            client_id = "service-dev-customer-api",
            client_secret = TestConstants.DummyValidServiceSecret,
            service_name = "Attacker Service",
            sub = "system:service:attacker",
            audience = "attacker-audience",
            permissions = new[] { "*" }
        };

        // Act
        var response = await Client.PostAsJsonAsync("/auth/v1/service/login", request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.NotNull(json.RootElement.GetProperty("access_token").GetString());
        Assert.NotEmpty(json.RootElement.GetProperty("access_token").GetString()!);
        Assert.Equal("Bearer", json.RootElement.GetProperty("token_type").GetString());
        Assert.True(json.RootElement.GetProperty("expires_in").GetInt32() > 0);

        // Service tokens should not have refresh tokens
        Assert.False(json.RootElement.TryGetProperty("refresh_token", out _));

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(
            json.RootElement.GetProperty("access_token").GetString());
        Assert.False(string.IsNullOrWhiteSpace(jwt.Header.Kid));
        Assert.Equal("test-issuer", jwt.Issuer);
        Assert.Contains("test-audience", jwt.Audiences);
        Assert.Equal(900, json.RootElement.GetProperty("expires_in").GetInt32());
        Assert.Equal(900, long.Parse(jwt.Claims.Single(c => c.Type == "exp").Value) -
            long.Parse(jwt.Claims.Single(c => c.Type == "iat").Value));
        Assert.Equal("11111111-1111-1111-1111-111111111111", jwt.Subject);
        Assert.Equal("service-dev-customer-api", jwt.Claims.Single(c => c.Type == "client_id").Value);
        Assert.Equal("Customer API Service", jwt.Claims.Single(c => c.Type == "service_name").Value);
        Assert.DoesNotContain(jwt.Claims, claim =>
            claim.Type == "permissions" && claim.Value == "*");
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_InvalidClientId_Returns401()
    {
        await CleanDatabaseAsync();
        // Arrange - Use properly formatted but non-existent client ID
        var request = new
        {
            client_id = "service-dev-nonexistent",
            client_secret = TestConstants.DummySecret
        };

        // Act
        var response = await Client.PostAsJsonAsync("/auth/v1/service/login", request);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(content);

        Assert.NotNull(json.RootElement.GetProperty("error").GetString());
        Assert.NotEmpty(json.RootElement.GetProperty("error").GetString()!);
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_InvalidClientSecret_Returns401()
    {
        await CleanDatabaseAsync();
        // Arrange
        var request = new
        {
            client_id = "service-dev-customer-api",
            client_secret = TestConstants.DummyWrongSecret
        };

        // Act
        var response = await Client.PostAsJsonAsync("/auth/v1/service/login", request);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_CrossServiceSwappedSecrets_ReturnsIndistinguishable401()
    {
        await CleanDatabaseAsync();
        const string secondClientId = "service-dev-order-api";
        const string secondSecret = "dummy_order_service_secret_456";
        await using (var context = Factory.GetDbContext())
        {
            context.ServiceCredentials.Add(new ServiceCredential
            {
                Id = Guid.NewGuid(),
                ClientId = secondClientId,
                PrincipalId = Guid.NewGuid(),
                ClientSecretHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secondSecret)))
                    .ToLowerInvariant(),
                ServiceName = "Order API Service",
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            });
            await context.SaveChangesAsync();
        }

        var firstWithSecondSecret = await Client.PostAsJsonAsync("/auth/v1/service/login", new
        {
            client_id = "service-dev-customer-api",
            client_secret = secondSecret
        });
        var secondWithFirstSecret = await Client.PostAsJsonAsync("/auth/v1/service/login", new
        {
            client_id = secondClientId,
            client_secret = TestConstants.DummyValidServiceSecret
        });

        Assert.Equal(HttpStatusCode.Unauthorized, firstWithSecondSecret.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, secondWithFirstSecret.StatusCode);
        Assert.Equal(
            await firstWithSecondSecret.Content.ReadAsStringAsync(),
            await secondWithFirstSecret.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task POST_V1_Auth_Service_Login_CredentialWithoutIamPrincipal_Returns503WithoutToken()
    {
        await CleanDatabaseAsync();
        const string clientId = "service-dev-unmapped-api";
        const string secret = "dummy_unmapped_service_secret_789";
        await using (var context = Factory.GetDbContext())
        {
            context.ServiceCredentials.Add(new ServiceCredential
            {
                Id = Guid.NewGuid(),
                ClientId = clientId,
                PrincipalId = null,
                ClientSecretHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secret)))
                    .ToLowerInvariant(),
                ServiceName = "Unmapped API Service",
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            });
            await context.SaveChangesAsync();
        }

        var response = await Client.PostAsJsonAsync("/auth/v1/service/login", new
        {
            client_id = clientId,
            client_secret = secret
        });

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("service_unavailable", json.RootElement.GetProperty("error").GetString());
        Assert.False(json.RootElement.TryGetProperty("access_token", out _));
    }
}
