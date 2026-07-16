using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Maliev.AuthService.Infrastructure.Security;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public sealed class TokenIssuanceCapabilitySignerTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 16, 4, 0, 0, TimeSpan.Zero);

    [Fact]
    public void CreateCapability_ValidConfiguration_ProducesExactTargetBoundClaims()
    {
        using var rsa = RSA.Create(2048);
        var options = new TokenIssuanceCapabilityOptions
        {
            ActiveKeyId = "auth-capability-2026-07",
            PrivateKey = rsa.ExportRSAPrivateKeyPem()
        };
        var signer = new TokenIssuanceCapabilitySigner(
            Options.Create(options),
            new FixedTimeProvider(Now));
        var target = Guid.Parse("11111111-1111-1111-1111-111111111111");

        var encoded = signer.CreateCapability(target);

        var token = new JwtSecurityTokenHandler().ReadJwtToken(encoded);
        Assert.Equal(SecurityAlgorithms.RsaSha256, token.Header.Alg);
        Assert.Equal(options.ActiveKeyId, token.Header.Kid);
        Assert.Equal(TokenIssuanceCapabilityOptions.Issuer, token.Issuer);
        Assert.Equal([TokenIssuanceCapabilityOptions.Audience], token.Audiences);
        AssertSingle(token, JwtRegisteredClaimNames.Sub, "urn:maliev:service:auth");
        AssertSingle(token, "service_name", "AuthService");
        AssertSingle(token, "client_id", "auth-service");
        AssertSingle(token, "user_type", "service");
        AssertSingle(token, "purpose", "iam.permission-resolution");
        AssertSingle(token, "target_principal_id", target.ToString("D"));
        AssertSingle(token, "permissions", "iam.auth.resolve-permissions");
        Assert.DoesNotContain(token.Claims, claim => claim.Type is "permission" or "role" or "roles");

        var jti = Assert.Single(token.Claims, claim => claim.Type == JwtRegisteredClaimNames.Jti).Value;
        Assert.True(Guid.TryParseExact(jti, "D", out _));
        var iat = long.Parse(Assert.Single(token.Claims, claim => claim.Type == JwtRegisteredClaimNames.Iat).Value);
        var nbf = long.Parse(Assert.Single(token.Claims, claim => claim.Type == JwtRegisteredClaimNames.Nbf).Value);
        var exp = long.Parse(Assert.Single(token.Claims, claim => claim.Type == JwtRegisteredClaimNames.Exp).Value);
        Assert.Equal(Now.ToUnixTimeSeconds(), iat);
        Assert.Equal(iat, nbf);
        Assert.Equal(30, exp - iat);
    }

    [Fact]
    public void CreateCapability_Twice_UsesUniqueCanonicalTokenIdentifiers()
    {
        using var rsa = RSA.Create(2048);
        var signer = new TokenIssuanceCapabilitySigner(
            Options.Create(new TokenIssuanceCapabilityOptions
            {
                ActiveKeyId = "active-key",
                PrivateKey = rsa.ExportPkcs8PrivateKeyPem()
            }),
            new FixedTimeProvider(Now));

        var first = new JwtSecurityTokenHandler().ReadJwtToken(signer.CreateCapability(Guid.NewGuid()));
        var second = new JwtSecurityTokenHandler().ReadJwtToken(signer.CreateCapability(Guid.NewGuid()));
        var firstJti = first.Claims.Single(claim => claim.Type == JwtRegisteredClaimNames.Jti).Value;
        var secondJti = second.Claims.Single(claim => claim.Type == JwtRegisteredClaimNames.Jti).Value;

        Assert.NotEqual(firstJti, secondJti);
        Assert.Equal(Guid.Parse(firstJti).ToString("D"), firstJti);
        Assert.Equal(Guid.Parse(secondJti).ToString("D"), secondJti);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(61)]
    public void CreateCapability_InvalidLifetime_FailsClosed(int lifetimeSeconds)
    {
        using var rsa = RSA.Create(2048);
        var signer = new TokenIssuanceCapabilitySigner(
            Options.Create(new TokenIssuanceCapabilityOptions
            {
                ActiveKeyId = "active-key",
                PrivateKey = rsa.ExportRSAPrivateKeyPem(),
                LifetimeSeconds = lifetimeSeconds
            }),
            new FixedTimeProvider(Now));

        Assert.Throws<InvalidOperationException>(() => signer.CreateCapability(Guid.NewGuid()));
    }

    [Fact]
    public void CreateCapability_MaximumLifetime_ProducesSixtySecondCapability()
    {
        using var rsa = RSA.Create(2048);
        var signer = new TokenIssuanceCapabilitySigner(
            Options.Create(new TokenIssuanceCapabilityOptions
            {
                ActiveKeyId = "active-key",
                PrivateKey = rsa.ExportRSAPrivateKeyPem(),
                LifetimeSeconds = 60
            }),
            new FixedTimeProvider(Now));

        var token = new JwtSecurityTokenHandler().ReadJwtToken(signer.CreateCapability(Guid.NewGuid()));
        var issuedAt = long.Parse(token.Claims.Single(claim => claim.Type == JwtRegisteredClaimNames.Iat).Value);
        var expiresAt = long.Parse(token.Claims.Single(claim => claim.Type == JwtRegisteredClaimNames.Exp).Value);

        Assert.Equal(60, expiresAt - issuedAt);
    }

    [Theory]
    [InlineData(null, "not-a-key")]
    [InlineData("", "not-a-key")]
    [InlineData("active-key", null)]
    [InlineData("active-key", "not-a-key")]
    public void CreateCapability_MissingOrInvalidSigningConfiguration_FailsAtCallTime(
        string? activeKeyId,
        string? privateKey)
    {
        var signer = new TokenIssuanceCapabilitySigner(
            Options.Create(new TokenIssuanceCapabilityOptions
            {
                ActiveKeyId = activeKeyId,
                PrivateKey = privateKey
            }),
            new FixedTimeProvider(Now));

        Assert.Throws<InvalidOperationException>(() => signer.CreateCapability(Guid.NewGuid()));
    }

    private static void AssertSingle(JwtSecurityToken token, string type, string value) =>
        Assert.Equal(value, Assert.Single(token.Claims, claim => claim.Type == type).Value);

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
