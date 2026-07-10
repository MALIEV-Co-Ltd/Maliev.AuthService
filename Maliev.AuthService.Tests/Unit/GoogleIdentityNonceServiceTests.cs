using Maliev.AuthService.Application.Identity;
using Maliev.AuthService.Infrastructure.DbContexts;
using Maliev.AuthService.Infrastructure.Services;
using Maliev.AuthService.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public sealed class GoogleIdentityNonceServiceTests : IClassFixture<TestDatabaseFixture>, IAsyncLifetime
{
    private readonly TestDatabaseFixture _fixture;

    public GoogleIdentityNonceServiceTests(TestDatabaseFixture fixture)
    {
        _fixture = fixture;
    }

    public async Task InitializeAsync()
    {
        await _fixture.InitializeAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task IssueAndConsumeAsync_StoresOnlyHashAndConsumesExactlyOnce()
    {
        await using var context = _fixture.CreateDbContext();
        var service = CreateService(context, TimeProvider.System);

        var issued = await service.IssueAsync(
            "WebBff",
            "web",
            GoogleIdentityExchangeType.Customer);

        var stored = await context.GoogleIdentityNonces.SingleAsync(nonce => nonce.Id == issued.Id);
        Assert.NotEqual(issued.Nonce, stored.NonceHash);
        Assert.Equal(64, stored.NonceHash.Length);

        Assert.True(await service.ConsumeAsync(
            issued.Nonce,
            "WebBff",
            "web",
            GoogleIdentityExchangeType.Customer));
        Assert.False(await service.ConsumeAsync(
            issued.Nonce,
            "WebBff",
            "web",
            GoogleIdentityExchangeType.Customer));
    }

    [Fact]
    public async Task ConsumeAsync_WrongCallerCannotConsumeAnotherApplicationsNonce()
    {
        await using var context = _fixture.CreateDbContext();
        var service = CreateService(context, TimeProvider.System);
        var issued = await service.IssueAsync(
            "QuoteEngineBff",
            "quote-engine",
            GoogleIdentityExchangeType.Customer);

        Assert.False(await service.ConsumeAsync(
            issued.Nonce,
            "WebBff",
            "quote-engine",
            GoogleIdentityExchangeType.Customer));
        Assert.False(await service.ConsumeAsync(
            issued.Nonce,
            "QuoteEngineBff",
            "web",
            GoogleIdentityExchangeType.Customer));
        Assert.True(await service.ConsumeAsync(
            issued.Nonce,
            "QuoteEngineBff",
            "quote-engine",
            GoogleIdentityExchangeType.Customer));
    }

    [Fact]
    public async Task ConsumeAsync_ExpiredNonceIsRejected()
    {
        await using var context = _fixture.CreateDbContext();
        var timeProvider = new MutableTimeProvider(DateTimeOffset.Parse("2026-07-10T00:00:00Z"));
        var service = CreateService(context, timeProvider);
        var issued = await service.IssueAsync(
            "IntranetBff",
            "intranet",
            GoogleIdentityExchangeType.Employee);

        timeProvider.Advance(TimeSpan.FromMinutes(11));

        Assert.False(await service.ConsumeAsync(
            issued.Nonce,
            "IntranetBff",
            "intranet",
            GoogleIdentityExchangeType.Employee));
    }

    [Fact]
    public async Task ConsumeAsync_ConcurrentConsumersAllowExactlyOneWinner()
    {
        GoogleIdentityNonceIssue issued;
        await using (var issueContext = _fixture.CreateDbContext())
        {
            var issuer = CreateService(issueContext, TimeProvider.System);
            issued = await issuer.IssueAsync(
                "WebBff",
                "web",
                GoogleIdentityExchangeType.Customer);
        }

        await using var firstContext = _fixture.CreateDbContext();
        await using var secondContext = _fixture.CreateDbContext();
        var firstConsumer = CreateService(firstContext, TimeProvider.System);
        var secondConsumer = CreateService(secondContext, TimeProvider.System);

        var results = await Task.WhenAll(
            firstConsumer.ConsumeAsync(
                issued.Nonce,
                "WebBff",
                "web",
                GoogleIdentityExchangeType.Customer),
            secondConsumer.ConsumeAsync(
                issued.Nonce,
                "WebBff",
                "web",
                GoogleIdentityExchangeType.Customer));

        Assert.Single(results, result => result);
        await using var verificationContext = _fixture.CreateDbContext();
        Assert.False(await verificationContext.GoogleIdentityNonces
            .AnyAsync(nonce => nonce.Id == issued.Id));
    }

    private static GoogleIdentityNonceService CreateService(
        AuthDbContext context,
        TimeProvider timeProvider)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["GoogleIdentity:NonceLifetimeMinutes"] = "10"
            })
            .Build();
        return new GoogleIdentityNonceService(context, configuration, timeProvider);
    }

    private sealed class MutableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan duration) => _now += duration;
    }
}
