using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Infrastructure.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Moq;
using System.Security.Cryptography;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public class TokenGeneratorAdditionalTests
{
    private readonly Mock<IConfiguration> _configMock;
    private readonly Mock<ILogger<TokenGenerator>> _loggerMock;
    private readonly Mock<IHostEnvironment> _envMock;

    public TokenGeneratorAdditionalTests()
    {
        _configMock = new Mock<IConfiguration>();
        _loggerMock = new Mock<ILogger<TokenGenerator>>();
        _envMock = new Mock<IHostEnvironment>();
    }

    private TokenGenerator CreateTokenGenerator()
    {
        var rsa = RSA.Create(2048);
        var privateKeyPem = rsa.ExportPkcs8PrivateKeyPem();
        var publicKeyPem = rsa.ExportRSAPublicKeyPem();

        _configMock.Setup(c => c["Jwt:PrivateKey"]).Returns(privateKeyPem);
        _configMock.Setup(c => c["Jwt:PublicKey"]).Returns(publicKeyPem);
        _configMock.Setup(c => c["Jwt:Issuer"]).Returns("test-issuer");
        _configMock.Setup(c => c["Jwt:Audience"]).Returns("test-audience");

        return new TokenGenerator(_configMock.Object, _loggerMock.Object, _envMock.Object);
    }

    [Fact]
    public void GenerateAccessToken_WithEmptyPermissions_GeneratesToken()
    {
        var service = CreateTokenGenerator();

        var token = service.GenerateAccessToken(
            Guid.NewGuid(),
            "customer",
            "test@example.com",
            "Test User",
            Enumerable.Empty<string>(),
            Enumerable.Empty<string>());

        Assert.NotNull(token);
        Assert.NotEmpty(token);
    }

    [Fact]
    public void GenerateAccessToken_WithManyPermissions_GeneratesToken()
    {
        var service = CreateTokenGenerator();

        var manyPermissions = Enumerable.Range(1, 50).Select(i => $"permission.{i}").ToList();

        var token = service.GenerateAccessToken(
            Guid.NewGuid(),
            "employee",
            "employee@maliev.com",
            "Employee",
            manyPermissions,
            new[] { "admin", "user" });

        Assert.NotNull(token);
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);

        var permissionsClaim = jwt.Claims.FirstOrDefault(c => c.Type == "permissions");
        Assert.NotNull(permissionsClaim);
    }

    [Fact]
    public void GenerateAccessToken_WithSpecialCharactersInEmail_GeneratesToken()
    {
        var service = CreateTokenGenerator();

        var token = service.GenerateAccessToken(
            Guid.NewGuid(),
            "customer",
            "user+test@subdomain.example.com",
            "User+Test",
            new[] { "read" },
            new[] { "user" });

        Assert.NotNull(token);
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);

        Assert.Equal("user+test@subdomain.example.com", jwt.Claims.First(c => c.Type == "email").Value);
    }

    [Fact]
    public void GenerateRefreshToken_ReturnsValidBase64String()
    {
        var service = CreateTokenGenerator();

        var token = service.GenerateRefreshToken();

        Assert.NotNull(token);
        Assert.NotEmpty(token);

        var parts = token.Split('.');
        Assert.NotNull(parts);
        Assert.NotEmpty(parts);
    }

    [Fact]
    public void HashToken_ProducesConsistentHash()
    {
        var service = CreateTokenGenerator();

        var hash1 = service.HashToken("test-token");
        var hash2 = service.HashToken("test-token");

        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void HashToken_DifferentInputs_ProduceDifferentHashes()
    {
        var service = CreateTokenGenerator();

        var hash1 = service.HashToken("token-1");
        var hash2 = service.HashToken("token-2");

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public async Task GenerateServiceAccessTokenAsync_WithoutPermissions_GeneratesToken()
    {
        var service = CreateTokenGenerator();

        var token = await service.GenerateServiceAccessTokenAsync(
            "test-service",
            "Test Service",
            null,
            null,
            null);

        Assert.NotNull(token);
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);

        Assert.Equal("test-service", jwt.Subject);
        Assert.Equal("service", jwt.Claims.First(c => c.Type == "user_type").Value);
    }

    [Fact]
    public void GenerateAccessToken_EmployeeType_GeneratesCorrectUserType()
    {
        var service = CreateTokenGenerator();

        var token = service.GenerateAccessToken(
            Guid.NewGuid(),
            "employee",
            "employee@maliev.com",
            "Employee",
            new[] { "manage" },
            new[] { "admin" });

        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);

        Assert.Equal("employee", jwt.Claims.First(c => c.Type == "user_type").Value);
    }
}
