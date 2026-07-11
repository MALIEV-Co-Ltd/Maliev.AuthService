using Maliev.AuthService.Domain.Entities;
using Maliev.AuthService.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Maliev.AuthService.Tests.Integration;

/// <summary>
/// PostgreSQL tests that quarantine credentials created by the former unverified registration flow.
/// </summary>
public sealed class PasskeyCredentialQuarantineTests(
    TestDatabaseFixture fixture) : IClassFixture<TestDatabaseFixture>, IAsyncLifetime
{
    /// <inheritdoc />
    public async Task InitializeAsync()
    {
        await fixture.InitializeAsync();
        await using var dbContext = fixture.CreateDbContext();
        await dbContext.PasskeyCredentials.ExecuteDeleteAsync();
    }

    /// <inheritdoc />
    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>Verifies pre-hardening rows default to unverified and have no trusted key material.</summary>
    [Fact]
    public async Task LegacyCredentialRow_IsQuarantinedByDefault()
    {
        var credentialId = Guid.NewGuid().ToString("N");
        await using var dbContext = fixture.CreateDbContext();
        await dbContext.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO passkey_credentials
                (id, principal_id, credential_id, public_key, device_name, sign_count, created_at_utc)
            VALUES
                ({Guid.NewGuid()}, {Guid.NewGuid()}, {credentialId}, {'p' + "em"}, {'l' + "egacy"}, {0}, {DateTime.UtcNow})
            """);

        var credential = await dbContext.PasskeyCredentials.AsNoTracking().SingleAsync();

        Assert.Equal(0, credential.RegistrationVerificationVersion);
        Assert.Null(credential.PublicKeyCose);
        Assert.Null(credential.UserHandle);
        Assert.Null(credential.VerifiedSignCount);
        Assert.Null(credential.IsBackupEligible);
        Assert.Null(credential.IsBackedUp);
    }

    /// <summary>Verifies verified authenticator state can represent the full unsigned WebAuthn counter range.</summary>
    [Fact]
    public async Task VerifiedCredential_PersistsTrustedAuthenticatorState()
    {
        await using var dbContext = fixture.CreateDbContext();
        var credential = CreateVerifiedCredential(uint.MaxValue);
        dbContext.PasskeyCredentials.Add(credential);

        await dbContext.SaveChangesAsync();
        dbContext.ChangeTracker.Clear();
        var stored = await dbContext.PasskeyCredentials.AsNoTracking().SingleAsync();

        Assert.Equal(1, stored.RegistrationVerificationVersion);
        Assert.Equal((long)uint.MaxValue, stored.VerifiedSignCount);
        Assert.NotNull(stored.PublicKeyCose);
        Assert.NotNull(stored.UserHandle);
        Assert.False(stored.IsBackupEligible);
        Assert.False(stored.IsBackedUp);
    }

    /// <summary>Verifies counters outside the WebAuthn uint32 range are rejected by PostgreSQL.</summary>
    [Fact]
    public async Task VerifiedCredential_CounterAboveUint32_IsRejected()
    {
        await using var dbContext = fixture.CreateDbContext();
        dbContext.PasskeyCredentials.Add(CreateVerifiedCredential((long)uint.MaxValue + 1));

        await Assert.ThrowsAsync<DbUpdateException>(() => dbContext.SaveChangesAsync());
    }

    private static PasskeyCredential CreateVerifiedCredential(long signCount) => new()
    {
        Id = Guid.NewGuid(),
        PrincipalId = Guid.NewGuid(),
        CredentialId = Guid.NewGuid().ToString("N"),
        PublicKey = string.Empty,
        PublicKeyCose = [1, 2, 3],
        UserHandle = Guid.NewGuid().ToByteArray(),
        DeviceName = "Verified test credential",
        RegistrationVerificationVersion = 1,
        VerifiedSignCount = signCount,
        IsBackupEligible = false,
        IsBackedUp = false,
        CreatedAtUtc = DateTime.UtcNow
    };
}
