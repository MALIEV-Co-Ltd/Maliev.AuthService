using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using Maliev.AuthService.Domain.Entities;
using Maliev.AuthService.Infrastructure.DbContexts;
using Maliev.AuthService.Infrastructure.Services;
using Maliev.AuthService.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public class TokenValidatorTests : IClassFixture<TestDatabaseFixture>, IAsyncLifetime
{
    private readonly TestDatabaseFixture _fixture;
    private readonly Mock<IConfiguration> _configMock;
    private readonly Mock<ILogger<TokenValidator>> _loggerMock;
    private TokenValidator? _service;
    private readonly string _publicKeyPem;
    private readonly string _privateKeyPem;

    public TokenValidatorTests(TestDatabaseFixture fixture)
    {
        _fixture = fixture;
        _loggerMock = new Mock<ILogger<TokenValidator>>();

        using var rsa = RSA.Create(2048);
        _privateKeyPem = rsa.ExportPkcs8PrivateKeyPem();
        _publicKeyPem = rsa.ExportSubjectPublicKeyInfoPem();

        _configMock = new Mock<IConfiguration>();
        _configMock.Setup(c => c["Jwt:PublicKey"]).Returns(_publicKeyPem);
        _configMock.Setup(c => c["Jwt:Issuer"]).Returns("https://test.com");
        _configMock.Setup(c => c["Jwt:Audience"]).Returns("https://test.com");
    }

    public async Task InitializeAsync()
    {
        await _fixture.InitializeAsync();
        _service = new TokenValidator(
            _configMock.Object,
            _fixture.CreateDbContext(),
            _loggerMock.Object);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private string GenerateValidToken()
    {
        var handler = new JwtSecurityTokenHandler();
        var rsa = RSA.Create();
        rsa.ImportFromPem(_privateKeyPem);

        var key = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsa);
        var credentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
            key, SecurityAlgorithms.RsaSha256);

        var token = handler.CreateJwtSecurityToken(
            issuer: "https://test.com",
            audience: "https://test.com",
            subject: new System.Security.Claims.ClaimsIdentity(new[]
            {
                new System.Security.Claims.Claim("sub", Guid.NewGuid().ToString()),
                new System.Security.Claims.Claim("jti", Guid.NewGuid().ToString()),
                new System.Security.Claims.Claim("user_type", "customer"),
                new System.Security.Claims.Claim("email", "test@test.com"),
                new System.Security.Claims.Claim("name", "Test User")
            }),
            signingCredentials: credentials,
            expires: DateTime.UtcNow.AddMinutes(15)
        );

        return handler.WriteToken(token);
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_ValidToken_ReturnsPrincipal()
    {
        // Arrange
        var token = GenerateValidToken();

        // Act
        var result = await _service!.ValidateAccessTokenAsync(token);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.FindFirst("sub"));
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_InvalidToken_ReturnsNull()
    {
        // Arrange
        var invalidToken = "not.a.valid.jwt.token";

        // Act
        var result = await _service!.ValidateAccessTokenAsync(invalidToken);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_MalformedToken_ReturnsNull()
    {
        // Arrange
        var malformedToken = "header.payload.signature";

        // Act
        var result = await _service!.ValidateAccessTokenAsync(malformedToken);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_ExpiredToken_ReturnsNull()
    {
        // Arrange
        var handler = new JwtSecurityTokenHandler();
        var rsa = RSA.Create();
        rsa.ImportFromPem(_privateKeyPem);

        var key = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsa);
        var credentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
            key, SecurityAlgorithms.RsaSha256);

        // Create token that expired 10 minutes ago (beyond the 5-minute clock skew)
        var now = DateTime.UtcNow;
        var token = handler.CreateJwtSecurityToken(
            issuer: "https://test.com",
            audience: "https://test.com",
            subject: new System.Security.Claims.ClaimsIdentity(new[]
            {
                new System.Security.Claims.Claim("sub", Guid.NewGuid().ToString()),
                new System.Security.Claims.Claim("jti", Guid.NewGuid().ToString())
            }),
            signingCredentials: credentials,
            notBefore: now.AddMinutes(-60),
            issuedAt: now.AddMinutes(-60),
            expires: now.AddMinutes(-10) // Expired 10 minutes ago (beyond 5-min clock skew)
        );

        // Act
        var result = await _service!.ValidateAccessTokenAsync(handler.WriteToken(token));

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_TamperedToken_ReturnsNull()
    {
        // Arrange
        var token = GenerateValidToken();
        var parts = token.Split('.');
        var tamperedToken = parts[0] + "." + parts[1] + ".tampered_signature";

        // Act
        var result = await _service!.ValidateAccessTokenAsync(tamperedToken);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_WrongIssuer_ReturnsNull()
    {
        // Arrange
        var handler = new JwtSecurityTokenHandler();
        var rsa = RSA.Create();
        rsa.ImportFromPem(_privateKeyPem);

        var key = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsa);
        var credentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
            key, SecurityAlgorithms.RsaSha256);

        var token = handler.CreateJwtSecurityToken(
            issuer: "https://wrong-issuer.com",
            audience: "https://test.com",
            subject: new System.Security.Claims.ClaimsIdentity(),
            signingCredentials: credentials,
            expires: DateTime.UtcNow.AddMinutes(15)
        );

        // Act
        var result = await _service!.ValidateAccessTokenAsync(handler.WriteToken(token));

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_WrongAudience_ReturnsNull()
    {
        // Arrange
        var handler = new JwtSecurityTokenHandler();
        var rsa = RSA.Create();
        rsa.ImportFromPem(_privateKeyPem);

        var key = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsa);
        var credentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
            key, SecurityAlgorithms.RsaSha256);

        var token = handler.CreateJwtSecurityToken(
            issuer: "https://test.com",
            audience: "https://wrong-audience.com",
            subject: new System.Security.Claims.ClaimsIdentity(),
            signingCredentials: credentials,
            expires: DateTime.UtcNow.AddMinutes(15)
        );

        // Act
        var result = await _service!.ValidateAccessTokenAsync(handler.WriteToken(token));

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task IsTokenRevokedAsync_RevokedToken_ReturnsTrue()
    {
        // Arrange
        var jti = Guid.NewGuid().ToString();
        using (var dbContext = _fixture.CreateDbContext())
        {
            dbContext.RevokedTokens.Add(new RevokedToken
            {
                Id = Guid.NewGuid(),
                Jti = jti,
                UserId = Guid.NewGuid(),
                UserType = UserType.Customer,
                RevokedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddMinutes(15)
            });
            await dbContext.SaveChangesAsync();
        }

        // Act
        var result = await _service!.IsTokenRevokedAsync(jti);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task IsTokenRevokedAsync_NotRevokedToken_ReturnsFalse()
    {
        // Arrange
        var jti = Guid.NewGuid().ToString();

        // Act
        var result = await _service!.IsTokenRevokedAsync(jti);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task IsTokenRevokedAsync_ExpiredRevokedToken_ReturnsFalse()
    {
        // Arrange
        var jti = Guid.NewGuid().ToString();
        using (var dbContext = _fixture.CreateDbContext())
        {
            dbContext.RevokedTokens.Add(new RevokedToken
            {
                Id = Guid.NewGuid(),
                Jti = jti,
                UserId = Guid.NewGuid(),
                UserType = UserType.Customer,
                RevokedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddMinutes(-1) // Expired
            });
            await dbContext.SaveChangesAsync();
        }

        // Act
        var result = await _service!.IsTokenRevokedAsync(jti);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_Base64PublicKey_Works()
    {
        // Arrange - create new validator with Base64 key
        var rsa = RSA.Create();
        rsa.ImportFromPem(_privateKeyPem);
        var publicKeyBase64 = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());

        var configMock = new Mock<IConfiguration>();
        configMock.Setup(c => c["Jwt:PublicKey"]).Returns(publicKeyBase64);
        configMock.Setup(c => c["Jwt:Issuer"]).Returns("https://test.com");
        configMock.Setup(c => c["Jwt:Audience"]).Returns("https://test.com");

        var service = new TokenValidator(
            configMock.Object,
            _fixture.CreateDbContext(),
            _loggerMock.Object);

        var token = GenerateValidToken();

        // Act
        var result = await service.ValidateAccessTokenAsync(token);

        // Assert
        Assert.NotNull(result);
    }
}
