using Maliev.AuthService.Domain.Entities;
using Maliev.AuthService.Infrastructure.Security;
using Maliev.AuthService.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Text.Json;
using Xunit;

namespace Maliev.AuthService.Tests.Integration;

/// <summary>
/// PostgreSQL integration tests for expiring, caller-bound, single-use passkey ceremonies.
/// </summary>
public sealed class PasskeyCeremonyStoreTests : IClassFixture<TestDatabaseFixture>, IAsyncLifetime
{
    private const string ServiceName = "WebBff";
    private const string Application = "web";
    private readonly TestDatabaseFixture _fixture;
    private readonly ManualTimeProvider _timeProvider = new(
        new DateTimeOffset(2026, 7, 11, 9, 0, 0, TimeSpan.Zero));

    /// <summary>Initializes the tests with the shared real-infrastructure fixture.</summary>
    /// <param name="fixture">The PostgreSQL, Redis, and RabbitMQ test fixture.</param>
    public PasskeyCeremonyStoreTests(TestDatabaseFixture fixture)
    {
        _fixture = fixture;
    }

    /// <inheritdoc />
    public async Task InitializeAsync()
    {
        await _fixture.InitializeAsync();
        await using var dbContext = _fixture.CreateDbContext();
        await dbContext.PasskeyAssertionCeremonies.ExecuteDeleteAsync();
    }

    /// <inheritdoc />
    public Task DisposeAsync()
    {
        return Task.CompletedTask;
    }

    /// <summary>Verifies a matching ceremony can be consumed only once.</summary>
    [Fact]
    public async Task ConsumeAsync_MatchingCallerAndApplication_IsSingleUse()
    {
        await using var dbContext = _fixture.CreateDbContext();
        var store = CreateStore(dbContext);
        var issued = await store.IssueAsync(
            ServiceName,
            Application,
            UserType.Customer,
            "{\"challenge\":\"server-owned\"}",
            new byte[32],
            CancellationToken.None);

        var first = await store.ConsumeAsync(
            issued.FlowId,
            ServiceName,
            Application,
            CancellationToken.None);
        var replay = await store.ConsumeAsync(
            issued.FlowId,
            ServiceName,
            Application,
            CancellationToken.None);

        Assert.NotNull(first);
        Assert.Equal(UserType.Customer, first.ExpectedUserType);
        using var options = JsonDocument.Parse(first.AssertionOptionsJson);
        Assert.Equal("server-owned", options.RootElement.GetProperty("challenge").GetString());
        Assert.Null(replay);
        Assert.Equal(0, await dbContext.PasskeyAssertionCeremonies.CountAsync());
    }

    /// <summary>Verifies the wrong service or application cannot consume another caller's flow.</summary>
    [Theory]
    [InlineData("QuoteEngineBff", Application)]
    [InlineData(ServiceName, "quote-engine")]
    public async Task ConsumeAsync_WrongCallerBoundary_DoesNotBurnCeremony(
        string serviceName,
        string application)
    {
        await using var dbContext = _fixture.CreateDbContext();
        var store = CreateStore(dbContext);
        var issued = await store.IssueAsync(
            ServiceName,
            Application,
            UserType.Customer,
            "{\"challenge\":\"bound\"}",
            Enumerable.Repeat((byte)7, 32).ToArray(),
            CancellationToken.None);

        var wrongBoundary = await store.ConsumeAsync(
            issued.FlowId,
            serviceName,
            application,
            CancellationToken.None);
        var correctBoundary = await store.ConsumeAsync(
            issued.FlowId,
            ServiceName,
            Application,
            CancellationToken.None);

        Assert.Null(wrongBoundary);
        Assert.NotNull(correctBoundary);
    }

    /// <summary>Verifies expired ceremonies cannot be consumed.</summary>
    [Fact]
    public async Task ConsumeAsync_ExpiredCeremony_IsRejected()
    {
        await using var dbContext = _fixture.CreateDbContext();
        var store = CreateStore(dbContext);
        var issued = await store.IssueAsync(
            ServiceName,
            Application,
            UserType.Customer,
            "{\"challenge\":\"expired\"}",
            Enumerable.Repeat((byte)9, 32).ToArray(),
            CancellationToken.None);
        _timeProvider.Advance(TimeSpan.FromMinutes(6));

        var result = await store.ConsumeAsync(
            issued.FlowId,
            ServiceName,
            Application,
            CancellationToken.None);

        Assert.Null(result);
    }

    /// <summary>Verifies the database contains only hashes of browser-visible flow and challenge values.</summary>
    [Fact]
    public async Task IssueAsync_PersistsOnlyFlowAndChallengeHashes()
    {
        await using var dbContext = _fixture.CreateDbContext();
        var store = CreateStore(dbContext);
        var challenge = Enumerable.Range(1, 32).Select(value => (byte)value).ToArray();
        var issued = await store.IssueAsync(
            ServiceName,
            Application,
            UserType.Customer,
            "{\"challenge\":\"hashed\"}",
            challenge,
            CancellationToken.None);

        var record = await dbContext.PasskeyAssertionCeremonies.AsNoTracking().SingleAsync();

        Assert.Equal(64, record.FlowIdHash.Length);
        Assert.Equal(64, record.ChallengeHash.Length);
        Assert.DoesNotContain(issued.FlowId, record.FlowIdHash, StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToBase64String(challenge), record.ChallengeHash, StringComparison.Ordinal);
        Assert.Equal(ServiceName.ToLowerInvariant(), record.ServiceName);
        Assert.Equal(Application, record.Application);
        Assert.Equal(UserType.Customer, record.ExpectedUserType);
    }

    /// <summary>Verifies one caller/application boundary cannot exceed its outstanding ceremony quota.</summary>
    [Fact]
    public async Task IssueAsync_BoundaryAtOutstandingLimit_RejectsAdditionalCeremony()
    {
        await using var dbContext = _fixture.CreateDbContext();
        var store = CreateStore(dbContext, maxOutstandingCeremonies: 1);
        await store.IssueAsync(
            ServiceName,
            Application,
            UserType.Customer,
            "{\"challenge\":\"first\"}",
            Enumerable.Repeat((byte)12, 32).ToArray(),
            CancellationToken.None);

        await Assert.ThrowsAsync<PasskeyCeremonyCapacityExceededException>(() =>
            store.IssueAsync(
                ServiceName,
                Application,
                UserType.Customer,
                "{\"challenge\":\"second\"}",
                Enumerable.Repeat((byte)13, 32).ToArray(),
                CancellationToken.None));

        Assert.Equal(1, await dbContext.PasskeyAssertionCeremonies.CountAsync());
    }

    /// <summary>Verifies expired ceremonies are removed before quota enforcement and release capacity.</summary>
    [Fact]
    public async Task IssueAsync_ExpiredCeremony_ReleasesBoundaryCapacity()
    {
        await using var dbContext = _fixture.CreateDbContext();
        var store = CreateStore(dbContext, maxOutstandingCeremonies: 1);
        var expired = await store.IssueAsync(
            ServiceName,
            Application,
            UserType.Customer,
            "{\"challenge\":\"expires\"}",
            Enumerable.Repeat((byte)14, 32).ToArray(),
            CancellationToken.None);
        _timeProvider.Advance(TimeSpan.FromMinutes(6));

        var replacement = await store.IssueAsync(
            ServiceName,
            Application,
            UserType.Customer,
            "{\"challenge\":\"replacement\"}",
            Enumerable.Repeat((byte)15, 32).ToArray(),
            CancellationToken.None);

        Assert.NotEqual(expired.FlowId, replacement.FlowId);
        Assert.Equal(1, await dbContext.PasskeyAssertionCeremonies.CountAsync());
    }

    /// <summary>Verifies one saturated application does not consume another trusted boundary's capacity.</summary>
    [Fact]
    public async Task IssueAsync_DifferentApplication_HasIndependentQuota()
    {
        await using var dbContext = _fixture.CreateDbContext();
        var store = CreateStore(dbContext, maxOutstandingCeremonies: 1);
        await store.IssueAsync(
            ServiceName,
            Application,
            UserType.Customer,
            "{\"challenge\":\"web\"}",
            Enumerable.Repeat((byte)16, 32).ToArray(),
            CancellationToken.None);

        var quoteEngine = await store.IssueAsync(
            "QuoteEngineBff",
            "quote-engine",
            UserType.Customer,
            "{\"challenge\":\"quote\"}",
            Enumerable.Repeat((byte)17, 32).ToArray(),
            CancellationToken.None);

        Assert.NotEmpty(quoteEngine.FlowId);
        Assert.Equal(2, await dbContext.PasskeyAssertionCeremonies.CountAsync());
    }

    /// <summary>Verifies concurrent issuers cannot race past one boundary's configured quota.</summary>
    [Fact]
    public async Task IssueAsync_ConcurrentRequestsAtLimit_HasExactlyOneWinner()
    {
        const int requestCount = 12;
        var contexts = Enumerable.Range(0, requestCount)
            .Select(_ => _fixture.CreateDbContext())
            .ToArray();
        try
        {
            var stores = contexts
                .Select(context => CreateStore(context, maxOutstandingCeremonies: 1))
                .ToArray();
            var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var attempts = stores.Select(async (store, index) =>
            {
                await start.Task;
                try
                {
                    await store.IssueAsync(
                        ServiceName,
                        Application,
                        UserType.Customer,
                        $"{{\"challenge\":\"concurrent-{index}\"}}",
                        Enumerable.Repeat(checked((byte)(index + 20)), 32).ToArray(),
                        CancellationToken.None);
                    return true;
                }
                catch (PasskeyCeremonyCapacityExceededException)
                {
                    return false;
                }
            }).ToArray();

            start.SetResult();
            var results = await Task.WhenAll(attempts);

            Assert.Single(results, issued => issued);
            await using var verificationContext = _fixture.CreateDbContext();
            Assert.Equal(1, await verificationContext.PasskeyAssertionCeremonies.CountAsync());
        }
        finally
        {
            foreach (var context in contexts)
            {
                await context.DisposeAsync();
            }
        }
    }

    /// <summary>Verifies two concurrent requests produce exactly one ceremony winner.</summary>
    [Fact]
    public async Task ConsumeAsync_ConcurrentReplay_HasExactlyOneWinner()
    {
        string flowId;
        await using (var issueContext = _fixture.CreateDbContext())
        {
            var issueStore = CreateStore(issueContext);
            var issued = await issueStore.IssueAsync(
                ServiceName,
                Application,
                UserType.Customer,
                "{\"challenge\":\"concurrent\"}",
                Enumerable.Repeat((byte)11, 32).ToArray(),
                CancellationToken.None);
            flowId = issued.FlowId;
        }

        await using var firstContext = _fixture.CreateDbContext();
        await using var secondContext = _fixture.CreateDbContext();
        var firstStore = CreateStore(firstContext);
        var secondStore = CreateStore(secondContext);

        var results = await Task.WhenAll(
            firstStore.ConsumeAsync(flowId, ServiceName, Application, CancellationToken.None),
            secondStore.ConsumeAsync(flowId, ServiceName, Application, CancellationToken.None));

        Assert.Single(results, result => result is not null);
    }

    private PasskeyCeremonyStore CreateStore(
        Maliev.AuthService.Infrastructure.DbContexts.AuthDbContext dbContext,
        int maxOutstandingCeremonies = 512) =>
        new(
            dbContext,
            Options.Create(new PasskeyWebAuthnOptions
            {
                CeremonyLifetimeMinutes = 5,
                MaxOutstandingCeremoniesPerApplication = maxOutstandingCeremonies
            }),
            _timeProvider);

    private sealed class ManualTimeProvider(DateTimeOffset initialUtcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = initialUtcNow;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan duration) => _utcNow = _utcNow.Add(duration);
    }
}
