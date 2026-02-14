using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using Maliev.AuthService.Api.Services;
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
}
