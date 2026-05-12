using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Maliev.AuthService.Infrastructure.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public class TokenGeneratorTests
{
    private readonly Mock<IConfiguration> _configMock;
    private readonly Mock<ILogger<TokenGenerator>> _loggerMock;
    private readonly Mock<IHostEnvironment> _environmentMock;
    private readonly TokenGenerator _tokenGenerator;
    private readonly string _privateKeyBase64;

    public TokenGeneratorTests()
    {
        _configMock = new Mock<IConfiguration>();
        _loggerMock = new Mock<ILogger<TokenGenerator>>();
        _environmentMock = new Mock<IHostEnvironment>();

        // Setup environment as Testing (not Development) to avoid debug logs in tests
        _environmentMock.Setup(e => e.EnvironmentName).Returns("Testing");

        using var rsa = RSA.Create(2048);
        var privateKeyPem = rsa.ExportPkcs8PrivateKeyPem();  // Use PKCS#8 format
        _privateKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(privateKeyPem));

        _configMock.Setup(c => c["Jwt:PrivateKey"]).Returns(_privateKeyBase64);
        _configMock.Setup(c => c["Jwt:Issuer"]).Returns("https://test.com");
        _configMock.Setup(c => c["Jwt:Audience"]).Returns("https://test.com");

        _tokenGenerator = new TokenGenerator(_configMock.Object, _loggerMock.Object, _environmentMock.Object);
    }

    [Fact]
    public void GenerateAccessToken_WithPermissions_ContainsPermissionsClaim()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var userType = "customer";
        var permissions = new List<string> { "order.orders.approve", "order.orders.cancel" };
        var roles = new List<string> { "manager" };

        // Act
        string tokenString = _tokenGenerator.GenerateAccessToken(userId, userType, null, null, permissions, roles);

        // Assert
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(tokenString);

        var permissionClaims = token.Claims.Where(c => c.Type == "permissions").Select(c => c.Value).ToList();
        var roleClaims = token.Claims.Where(c => c.Type == "roles").Select(c => c.Value).ToList();

        Assert.Equal(2, permissionClaims.Count);
        Assert.Contains("order.orders.approve", permissionClaims);
        Assert.Contains("order.orders.cancel", permissionClaims);
        Assert.Single(roleClaims);
        Assert.Equal("manager", roleClaims[0]);
    }

    [Fact]
    public void GenerateAccessToken_With100Permissions_TokenSizeIsReasonable()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var userType = "customer";
        var permissions = Enumerable.Range(1, 100).Select(i => $"service_{i:D2}.resource_{i:D2}.action_{i:D2}").ToList();

        // Act
        string tokenString = _tokenGenerator.GenerateAccessToken(userId, userType, null, null, permissions, null);

        // Assert
        // Standard JWT size for 100 permissions should be around 4-6 KB.
        // We want to ensure it's under 8KB (SC-005).
        var sizeInBytes = Encoding.UTF8.GetByteCount(tokenString);

        Assert.True(sizeInBytes < 8192, $"Token size is {sizeInBytes} bytes, which exceeds 8KB limit.");
    }

    [Fact]
    public void GenerateRefreshToken_ReturnsValidBase64Token()
    {
        // Act
        var token = _tokenGenerator.GenerateRefreshToken();

        // Assert
        Assert.NotNull(token);
        Assert.True(token.Length > 20);

        // Verify it's valid base64
        var bytes = Convert.FromBase64String(token);
        Assert.Equal(32, bytes.Length);
    }

    [Fact]
    public void HashToken_ReturnsConsistentHash()
    {
        // Arrange
        var token = "test-token";

        // Act
        var hash1 = _tokenGenerator.HashToken(token);
        var hash2 = _tokenGenerator.HashToken(token);

        // Assert
        Assert.Equal(hash1, hash2);
        Assert.Equal(64, hash1.Length); // SHA256 produces 32 bytes = 64 hex chars
    }

    [Fact]
    public async Task GenerateServiceAccessTokenAsync_WithPermissions_ReturnsToken()
    {
        // Arrange
        var clientId = "test-service";
        var serviceName = "Test Service";
        var permissions = new List<string> { "service.resources.read" };
        var roles = new List<string> { "service-role" };
        var principalId = Guid.NewGuid();

        // Act
        var token = await _tokenGenerator.GenerateServiceAccessTokenAsync(clientId, serviceName, permissions, roles, principalId);

        // Assert
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);

        Assert.Equal("service", jwt.Claims.First(c => c.Type == "user_type").Value);
        Assert.Equal(clientId, jwt.Claims.First(c => c.Type == "client_id").Value);
        Assert.Equal(serviceName, jwt.Claims.First(c => c.Type == "service_name").Value);
    }

    [Fact]
    public async Task GenerateServiceAccessTokenAsync_WithoutPrincipalId_UsesClientId()
    {
        // Arrange
        var clientId = "test-service-no-principal";
        var serviceName = "Test Service";

        // Act
        var token = await _tokenGenerator.GenerateServiceAccessTokenAsync(clientId, serviceName, null, null, null);

        // Assert
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);

        Assert.Equal(clientId, jwt.Subject);
    }

    [Fact]
    public void GenerateAccessToken_WithNoEmailOrName_StillGeneratesToken()
    {
        // Arrange
        var userId = Guid.NewGuid();

        // Act
        string tokenString = _tokenGenerator.GenerateAccessToken(userId, "customer", null, null, null, null);

        // Assert
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(tokenString);

        Assert.NotNull(token);
        Assert.Equal(userId.ToString(), token.Subject);
    }

    [Fact]
    public void GenerateAccessToken_WithRoles_ContainsRoleClaims()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var roles = new List<string> { "admin", "user" };

        // Act
        string tokenString = _tokenGenerator.GenerateAccessToken(userId, "employee", "test@test.com", "Test User", null, roles);

        // Assert
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(tokenString);

        var roleClaims = token.Claims.Where(c => c.Type == "roles").Select(c => c.Value).ToList();
        Assert.Contains("admin", roleClaims);
        Assert.Contains("user", roleClaims);
    }

    [Fact]
    public void GenerateAccessToken_ForCustomerSession_ContainsPrincipalAndCustomerClaims()
    {
        // Arrange
        var principalId = Guid.NewGuid();
        var customerId = Guid.NewGuid();

        // Act
        var tokenString = _tokenGenerator.GenerateAccessToken(
            principalId,
            "customer",
            "customer@example.com",
            "Customer",
            null,
            null,
            customerId);

        // Assert
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(tokenString);

        Assert.Equal(principalId.ToString(), token.Subject);
        Assert.Equal(principalId.ToString(), token.Claims.First(c => c.Type == "principal_id").Value);
        Assert.Equal(customerId.ToString(), token.Claims.First(c => c.Type == "customer_id").Value);
    }
}
