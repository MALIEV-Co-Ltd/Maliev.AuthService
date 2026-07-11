using Fido2NetLib;
using Fido2NetLib.Objects;
using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Domain.Entities;
using Maliev.AuthService.Infrastructure.Security;
using Maliev.AuthService.Infrastructure.Services;
using Maliev.AuthService.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Maliev.AuthService.Tests.Integration;

/// <summary>
/// PostgreSQL integration tests for passkey authentication orchestration and credential quarantine.
/// </summary>
public sealed class PasskeyAuthenticationServiceTests(
    TestDatabaseFixture fixture) : IClassFixture<TestDatabaseFixture>, IAsyncLifetime
{
    private const string ServiceName = "WebBff";
    private const string Application = "web";
    private const string RpId = "maliev.test";
    private const string Origin = "https://app.maliev.test";
    private readonly ManualTimeProvider _timeProvider = new(
        new DateTimeOffset(2026, 7, 11, 10, 0, 0, TimeSpan.Zero));

    /// <inheritdoc />
    public async Task InitializeAsync()
    {
        await fixture.InitializeAsync();
        await using var dbContext = fixture.CreateDbContext();
        await dbContext.PasskeyAssertionCeremonies.ExecuteDeleteAsync();
        await dbContext.PasskeyCredentials.ExecuteDeleteAsync();
        await dbContext.UserPrincipals.ExecuteDeleteAsync();
    }

    /// <inheritdoc />
    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>Verifies a verified credential can authenticate once and commits authenticator state first.</summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_VerifiedCredential_ReturnsCanonicalPrincipalAndRejectsReplay()
    {
        await using var dbContext = fixture.CreateDbContext();
        var seeded = await SeedVerifiedCredentialAsync(dbContext);
        var verifier = SuccessfulVerifier(signCount: 9, isBackedUp: true);
        var service = CreateService(dbContext, verifier.Object);
        var begin = await service.BeginAuthenticationAsync(
            new PasskeyAuthBeginRequest { Application = Application },
            ServiceName,
            CancellationToken.None);
        Assert.NotNull(begin);

        var request = CreateCompleteRequest(
            begin.FlowId,
            seeded.CredentialId,
            ToBase64Url(seeded.UserHandle));
        var first = await service.CompleteAuthenticationAsync(
            request,
            ServiceName,
            CancellationToken.None);
        var replay = await service.CompleteAuthenticationAsync(
            request,
            ServiceName,
            CancellationToken.None);

        Assert.True(first.Success);
        Assert.Equal(seeded.PrincipalId, first.PrincipalId);
        Assert.Equal("verified@example.test", first.Email);
        Assert.False(replay.Success);
        var verificationInput = Assert.IsType<PasskeyAssertionVerificationInput>(
            Assert.Single(verifier.Invocations).Arguments[0]);
        var assertionOptions = AssertionOptions.FromJson(verificationInput.AssertionOptionsJson);
        Assert.Equal(begin.Challenge, ToBase64Url(assertionOptions.Challenge));
        Assert.Equal(request.CredentialId, verificationInput.CredentialId);
        Assert.Equal(request.AuthenticatorData, verificationInput.AuthenticatorData);
        Assert.Equal(request.ClientDataJson, verificationInput.ClientDataJson);
        Assert.Equal(request.Signature, verificationInput.Signature);
        Assert.Equal(request.UserHandle, verificationInput.UserHandle);
        Assert.Equal(FromBase64Url(seeded.CredentialId), verificationInput.StoredCredentialId);
        Assert.Equal(seeded.PublicKeyCose, verificationInput.StoredPublicKeyCose);
        Assert.Equal(seeded.UserHandle, verificationInput.StoredUserHandle);
        Assert.Equal((uint)1, verificationInput.StoredSignCount);
        Assert.False(verificationInput.StoredBackupEligible);
        dbContext.ChangeTracker.Clear();
        var stored = await dbContext.PasskeyCredentials.AsNoTracking().SingleAsync();
        Assert.Equal(9, stored.VerifiedSignCount);
        Assert.True(stored.IsBackedUp);
        Assert.Equal(_timeProvider.GetUtcNow().UtcDateTime, stored.LastUsedAtUtc);
    }

    /// <summary>Verifies legacy browser-authored credentials never reach cryptographic verification.</summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_LegacyCredential_IsQuarantined()
    {
        await using var dbContext = fixture.CreateDbContext();
        var seeded = await SeedVerifiedCredentialAsync(dbContext, verificationVersion: 0);
        var verifier = SuccessfulVerifier(2, false);
        var service = CreateService(dbContext, verifier.Object);
        var begin = await service.BeginAuthenticationAsync(
            new PasskeyAuthBeginRequest { Application = Application },
            ServiceName,
            CancellationToken.None);

        var result = await service.CompleteAuthenticationAsync(
            CreateCompleteRequest(
                begin!.FlowId,
                seeded.CredentialId,
                ToBase64Url(seeded.UserHandle)),
            ServiceName,
            CancellationToken.None);

        Assert.False(result.Success);
        verifier.VerifyNoOtherCalls();
    }

    /// <summary>Verifies customer applications cannot authenticate an employee credential.</summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_EmployeeCredentialForCustomerApplication_IsRejected()
    {
        await using var dbContext = fixture.CreateDbContext();
        var seeded = await SeedVerifiedCredentialAsync(dbContext, userType: UserType.Employee);
        var verifier = SuccessfulVerifier(2, false);
        var service = CreateService(dbContext, verifier.Object);
        var begin = await service.BeginAuthenticationAsync(
            new PasskeyAuthBeginRequest { Application = Application },
            ServiceName,
            CancellationToken.None);

        var result = await service.CompleteAuthenticationAsync(
            CreateCompleteRequest(
                begin!.FlowId,
                seeded.CredentialId,
                ToBase64Url(seeded.UserHandle)),
            ServiceName,
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Null(result.PrincipalId);
        Assert.Null(result.Email);
        verifier.VerifyNoOtherCalls();
        dbContext.ChangeTracker.Clear();
        var stored = await dbContext.PasskeyCredentials.AsNoTracking().SingleAsync();
        Assert.Equal(1, stored.VerifiedSignCount);
        Assert.Null(stored.LastUsedAtUtc);
    }

    /// <summary>Verifies the service caller and application audience are enforced without burning the flow.</summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_WrongCallerBoundary_DoesNotConsumeCeremony()
    {
        await using var dbContext = fixture.CreateDbContext();
        var seeded = await SeedVerifiedCredentialAsync(dbContext);
        var verifier = SuccessfulVerifier(2, false);
        var service = CreateService(dbContext, verifier.Object);
        var begin = await service.BeginAuthenticationAsync(
            new PasskeyAuthBeginRequest { Application = Application },
            ServiceName,
            CancellationToken.None);
        var request = CreateCompleteRequest(
            begin!.FlowId,
            seeded.CredentialId,
            ToBase64Url(seeded.UserHandle));

        var wrongCaller = await service.CompleteAuthenticationAsync(
            request,
            "QuoteEngineBff",
            CancellationToken.None);
        var correctCaller = await service.CompleteAuthenticationAsync(
            request,
            ServiceName,
            CancellationToken.None);

        Assert.False(wrongCaller.Success);
        Assert.True(correctCaller.Success);
    }

    /// <summary>Verifies an expired ceremony never reaches the assertion verifier.</summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_ExpiredCeremony_IsRejected()
    {
        await using var dbContext = fixture.CreateDbContext();
        var seeded = await SeedVerifiedCredentialAsync(dbContext);
        var verifier = SuccessfulVerifier(2, false);
        var service = CreateService(dbContext, verifier.Object);
        var begin = await service.BeginAuthenticationAsync(
            new PasskeyAuthBeginRequest { Application = Application },
            ServiceName,
            CancellationToken.None);
        _timeProvider.Advance(TimeSpan.FromMinutes(6));

        var result = await service.CompleteAuthenticationAsync(
            CreateCompleteRequest(
                begin!.FlowId,
                seeded.CredentialId,
                ToBase64Url(seeded.UserHandle)),
            ServiceName,
            CancellationToken.None);

        Assert.False(result.Success);
        verifier.VerifyNoOtherCalls();
    }

    /// <summary>Verifies an invalid assertion consumes its challenge and cannot be corrected through replay.</summary>
    [Fact]
    public async Task CompleteAuthenticationAsync_InvalidAssertion_ConsumesCeremony()
    {
        await using var dbContext = fixture.CreateDbContext();
        var seeded = await SeedVerifiedCredentialAsync(dbContext);
        var verifier = new Mock<IPasskeyAssertionVerifier>();
        verifier.Setup(candidate => candidate.VerifyAsync(
                It.IsAny<PasskeyAssertionVerificationInput>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(PasskeyAssertionVerificationResult.Failed(
                PasskeyAssertionFailure.VerificationFailed));
        var service = CreateService(dbContext, verifier.Object);
        var begin = await service.BeginAuthenticationAsync(
            new PasskeyAuthBeginRequest { Application = Application },
            ServiceName,
            CancellationToken.None);
        var request = CreateCompleteRequest(
            begin!.FlowId,
            seeded.CredentialId,
            ToBase64Url(seeded.UserHandle));

        var invalid = await service.CompleteAuthenticationAsync(
            request,
            ServiceName,
            CancellationToken.None);
        verifier.Reset();
        verifier.Setup(candidate => candidate.VerifyAsync(
                It.IsAny<PasskeyAssertionVerificationInput>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAssertionVerificationResult(
                true,
                2,
                false,
                PasskeyAssertionFailure.None));
        var correctedReplay = await service.CompleteAuthenticationAsync(
            request,
            ServiceName,
            CancellationToken.None);

        Assert.False(invalid.Success);
        Assert.False(correctedReplay.Success);
        verifier.VerifyNoOtherCalls();
    }

    /// <summary>Verifies disabled or user-scoped begin requests fail without storing a ceremony.</summary>
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public async Task BeginAuthenticationAsync_DisabledOrPrincipalScoped_DoesNotIssueFlow(
        bool enabled,
        bool principalScoped)
    {
        await using var dbContext = fixture.CreateDbContext();
        var service = CreateService(
            dbContext,
            SuccessfulVerifier(1, false).Object,
            enabled);

        var result = await service.BeginAuthenticationAsync(
            new PasskeyAuthBeginRequest
            {
                Application = Application,
                PrincipalId = principalScoped ? Guid.NewGuid() : null
            },
            ServiceName,
            CancellationToken.None);

        Assert.Null(result);
        Assert.False(await dbContext.PasskeyAssertionCeremonies.AnyAsync());
    }

    private PasskeyService CreateService(
        Maliev.AuthService.Infrastructure.DbContexts.AuthDbContext dbContext,
        IPasskeyAssertionVerifier verifier,
        bool enabled = true)
    {
        var options = Options.Create(new PasskeyWebAuthnOptions
        {
            Enabled = enabled,
            RpId = RpId,
            RpName = "MALIEV Test",
            AllowedOrigins = [Origin],
            TimeoutMilliseconds = 300_000,
            ChallengeSize = 32,
            CeremonyLifetimeMinutes = 5,
            Bindings = new Dictionary<string, PasskeyApplicationBinding>
            {
                [Application] = new()
                {
                    ServiceName = ServiceName,
                    PrincipalType = UserType.Customer
                }
            }
        });
        var fido2 = new Fido2(new Fido2Configuration
        {
            ServerDomain = RpId,
            ServerName = "MALIEV Test",
            Origins = new HashSet<string>([Origin], StringComparer.Ordinal),
            Timeout = 300_000,
            ChallengeSize = 32
        });
        return new PasskeyService(
            dbContext,
            new PasskeyCeremonyStore(dbContext, options, _timeProvider),
            verifier,
            fido2,
            options,
            _timeProvider,
            NullLogger<PasskeyService>.Instance);
    }

    private async Task<(
        Guid PrincipalId,
        string CredentialId,
        byte[] PublicKeyCose,
        byte[] UserHandle)> SeedVerifiedCredentialAsync(
        Maliev.AuthService.Infrastructure.DbContexts.AuthDbContext dbContext,
        int verificationVersion = 1,
        UserType userType = UserType.Customer)
    {
        var principalId = Guid.NewGuid();
        var credentialId = ToBase64Url(Guid.NewGuid().ToByteArray());
        byte[] publicKeyCose = [1, 2, 3];
        var userHandle = Guid.NewGuid().ToByteArray();
        dbContext.UserPrincipals.Add(new UserPrincipal
        {
            Id = principalId,
            Email = "verified@example.test",
            FirstName = "Verified",
            LastName = "Customer",
            UserType = userType,
            EmailVerifiedAtUtc = _timeProvider.GetUtcNow().UtcDateTime,
            CreatedAt = _timeProvider.GetUtcNow().UtcDateTime,
            UpdatedAt = _timeProvider.GetUtcNow().UtcDateTime
        });
        dbContext.PasskeyCredentials.Add(new PasskeyCredential
        {
            Id = Guid.NewGuid(),
            PrincipalId = principalId,
            CredentialId = credentialId,
            PublicKey = string.Empty,
            PublicKeyCose = publicKeyCose,
            UserHandle = userHandle,
            DeviceName = "Verified test credential",
            RegistrationVerificationVersion = verificationVersion,
            VerifiedSignCount = 1,
            IsBackupEligible = false,
            IsBackedUp = false,
            SignCount = 0,
            CreatedAtUtc = _timeProvider.GetUtcNow().UtcDateTime
        });
        await dbContext.SaveChangesAsync();
        return (principalId, credentialId, publicKeyCose, userHandle);
    }

    private static Mock<IPasskeyAssertionVerifier> SuccessfulVerifier(
        uint signCount,
        bool isBackedUp)
    {
        var verifier = new Mock<IPasskeyAssertionVerifier>();
        verifier.Setup(candidate => candidate.VerifyAsync(
                It.IsAny<PasskeyAssertionVerificationInput>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PasskeyAssertionVerificationResult(
                true,
                signCount,
                isBackedUp,
                PasskeyAssertionFailure.None));
        return verifier;
    }

    private static PasskeyAuthCompleteRequest CreateCompleteRequest(
        string flowId,
        string credentialId,
        string userHandle) => new()
    {
        Application = Application,
        FlowId = flowId,
        CredentialId = credentialId,
        AuthenticatorData = "AQ",
        ClientDataJson = "e30",
        Signature = "AQ",
        UserHandle = userHandle
    };

    private static byte[] FromBase64Url(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }

    private static string ToBase64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed class ManualTimeProvider(DateTimeOffset initialUtcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = initialUtcNow;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan duration) => _utcNow = _utcNow.Add(duration);
    }
}
