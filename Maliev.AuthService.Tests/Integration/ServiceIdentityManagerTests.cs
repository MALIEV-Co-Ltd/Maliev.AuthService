using Maliev.AuthService.Application.DTOs.IAM;
using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Domain.Entities;
using Maliev.AuthService.Infrastructure.Services;
using Maliev.AuthService.Tests.Contract;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Maliev.AuthService.Tests.Integration;

[Collection("AuthService Collection")]
public sealed class ServiceIdentityManagerTests(TestWebApplicationFactory factory) : IAsyncLifetime
{
    private static readonly Guid ActorId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private const string WorkloadId = "auth-service";
    private const string ExpectedRoleId = "roles.workloads.auth-service.v1";

    public Task InitializeAsync() => factory.CleanDatabaseAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task ProvisionAsync_SameOperationReplay_ReturnsSecretOnceAndCallsIamOnce()
    {
        await using var context = factory.CreateDbContext();
        var iam = new RecordingIamClient();
        var manager = new ServiceIdentityManager(context, iam, TimeProvider.System);
        var request = NewProvisionRequest();

        var created = await manager.ProvisionAsync(WorkloadId, request, ActorId, "employee-token");
        context.ChangeTracker.Clear();
        var replay = await manager.ProvisionAsync(WorkloadId, request, ActorId, "employee-token");

        Assert.True(created.SecretRetrievable);
        Assert.NotNull(created.ClientSecret);
        Assert.True(created.ClientSecret.Length >= 43);
        Assert.False(replay.SecretRetrievable);
        Assert.Null(replay.ClientSecret);
        Assert.Equal(1, iam.CallCount);
        Assert.Equal("employee-token", iam.LastBearerToken);

        var persisted = await context.ServiceCredentialVersions.AsNoTracking().SingleAsync();
        Assert.NotEqual(created.ClientSecret, persisted.SecretHash);
        Assert.Equal(64, persisted.SecretHash.Length);
        Assert.DoesNotContain(created.ClientSecret, await DumpStringColumnsAsync(context));
    }

    [Fact]
    public async Task ProvisionAsync_ReusedOperationFromAnotherActor_Conflicts()
    {
        await using var context = factory.CreateDbContext();
        var manager = new ServiceIdentityManager(context, new RecordingIamClient(), TimeProvider.System);
        var request = NewProvisionRequest();
        _ = await manager.ProvisionAsync(WorkloadId, request, ActorId, "employee-token");
        context.ChangeTracker.Clear();

        await Assert.ThrowsAsync<ServiceIdentityConflictException>(() => manager.ProvisionAsync(
            WorkloadId,
            request,
            Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            "employee-token"));
    }

    [Fact]
    public async Task ProvisionAsync_IamReadySaga_ResumesWithoutCallingIamAgain()
    {
        await using var context = factory.CreateDbContext();
        var request = NewProvisionRequest();
        var operation = new ServiceIdentityOperation
        {
            Id = request.OperationId,
            WorkloadId = WorkloadId,
            Kind = ServiceIdentityOperationKind.Provision,
            RequestHash = HashCanonicalRequest(
                $"provision|{WorkloadId}|{request.ProfileVersion}|{request.ServiceName}|{request.HardExpiryDays}"),
            ActorId = ActorId,
            State = ServiceIdentityOperationState.IamReady,
            IamPrincipalId = Guid.Parse("11111111-1111-1111-1111-111111111111"),
            IamProfileVersion = 1,
            IamRoleId = ExpectedRoleId,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };
        context.ServiceIdentityOperations.Add(operation);
        await context.SaveChangesAsync();
        var iam = new RecordingIamClient { ThrowOnCall = true };
        var manager = new ServiceIdentityManager(context, iam, TimeProvider.System);

        var result = await manager.ProvisionAsync(WorkloadId, request, ActorId, "employee-token");

        Assert.True(result.SecretRetrievable);
        Assert.Equal(0, iam.CallCount);
        Assert.True(await context.ServiceCredentials.AnyAsync(item => item.WorkloadId == WorkloadId));
    }

    [Fact]
    public async Task ProvisionAsync_ConcurrentSameOperation_ProducesOneVersionAndOneSecretResponse()
    {
        var request = NewProvisionRequest();
        var iam = new RecordingIamClient();
        await using var firstContext = factory.CreateDbContext();
        await using var secondContext = factory.CreateDbContext();
        var firstManager = new ServiceIdentityManager(firstContext, iam, TimeProvider.System);
        var secondManager = new ServiceIdentityManager(secondContext, iam, TimeProvider.System);

        var results = await Task.WhenAll(
            firstManager.ProvisionAsync(WorkloadId, request, ActorId, "employee-token"),
            secondManager.ProvisionAsync(WorkloadId, request, ActorId, "employee-token"));

        Assert.Single(results, result => result.SecretRetrievable);
        Assert.Single(results, result => !result.SecretRetrievable);
        Assert.Equal(1, iam.CallCount);
        await using var verificationContext = factory.CreateDbContext();
        Assert.Equal(1, await verificationContext.ServiceCredentialVersions.CountAsync());
    }

    [Fact]
    public async Task ProvisionAsync_ExistingIdentityWithDifferentLifecycleParameters_Conflicts()
    {
        await using var context = factory.CreateDbContext();
        var manager = new ServiceIdentityManager(context, new RecordingIamClient(), TimeProvider.System);
        _ = await manager.ProvisionAsync(WorkloadId, NewProvisionRequest(), ActorId, "employee-token");
        context.ChangeTracker.Clear();

        await Assert.ThrowsAsync<ServiceIdentityConflictException>(() => manager.ProvisionAsync(
            WorkloadId,
            new ProvisionServiceIdentityRequest
            {
                OperationId = Guid.NewGuid(),
                ProfileVersion = 1,
                ServiceName = "Another Service",
                HardExpiryDays = 30
            },
            ActorId,
            "employee-token"));
    }

    [Theory]
    [InlineData("other", ExpectedRoleId)]
    [InlineData(WorkloadId, "*")]
    [InlineData(WorkloadId, "roles.iam.admin")]
    [InlineData(WorkloadId, "roles.workloads.other.v1")]
    [InlineData(WorkloadId, "roles.workloads.auth-service.v2")]
    public async Task ProvisionAsync_UnsafeIamResponse_DoesNotCreateCredential(
        string returnedWorkload,
        string returnedRole)
    {
        await using var context = factory.CreateDbContext();
        var iam = new RecordingIamClient
        {
            Response = new WorkloadPrincipalResponse
            {
                WorkloadId = returnedWorkload,
                PrincipalId = Guid.Parse("11111111-1111-1111-1111-111111111111"),
                ProfileVersion = 1,
                RoleId = returnedRole
            }
        };
        var manager = new ServiceIdentityManager(context, iam, TimeProvider.System);

        await Assert.ThrowsAsync<ServiceIdentityConflictException>(() => manager.ProvisionAsync(
            WorkloadId,
            NewProvisionRequest(),
            ActorId,
            "employee-token"));

        Assert.False(await context.ServiceCredentials.AnyAsync(item => item.WorkloadId == WorkloadId));
        Assert.False(await context.ServiceCredentialVersions.AnyAsync());
    }

    [Fact]
    public async Task RotateAndRevokeAsync_TransitionsActiveGraceAndRevokedAtomically()
    {
        await using var context = factory.CreateDbContext();
        var manager = new ServiceIdentityManager(context, new RecordingIamClient(), TimeProvider.System);
        var created = await manager.ProvisionAsync(WorkloadId, NewProvisionRequest(), ActorId, "employee-token");
        context.ChangeTracker.Clear();

        var rotated = await manager.RotateAsync(
            WorkloadId,
            new RotateServiceIdentityRequest
            {
                OperationId = Guid.NewGuid(),
                GracePeriodSeconds = 60,
                HardExpiryDays = 30
            },
            ActorId);

        Assert.NotEqual(created.ClientSecret, rotated.ClientSecret);
        var versions = await context.ServiceCredentialVersions
            .AsNoTracking()
            .OrderBy(item => item.Version)
            .ToListAsync();
        Assert.Equal(ServiceCredentialVersionStatus.Grace, versions[0].Status);
        Assert.Equal(ServiceCredentialVersionStatus.Active, versions[1].Status);
        var logicalHash = await context.ServiceCredentials.AsNoTracking()
            .Where(item => item.WorkloadId == WorkloadId)
            .Select(item => item.ClientSecretHash)
            .SingleAsync();
        Assert.Equal(Hash(rotated.ClientSecret!), logicalHash);

        context.ChangeTracker.Clear();
        await manager.RevokeAsync(
            WorkloadId,
            new RevokeServiceIdentityRequest { OperationId = Guid.NewGuid() },
            ActorId);
        Assert.False(await context.ServiceCredentials.AsNoTracking().Where(item => item.WorkloadId == WorkloadId)
            .Select(item => item.IsActive).SingleAsync());
        Assert.All(
            await context.ServiceCredentialVersions.AsNoTracking().ToListAsync(),
            version => Assert.Equal(ServiceCredentialVersionStatus.Revoked, version.Status));
    }

    [Fact]
    public async Task RotateAsync_Twice_OnlyImmediatePriorSecretRemainsGrace()
    {
        await using var context = factory.CreateDbContext();
        var manager = new ServiceIdentityManager(context, new RecordingIamClient(), TimeProvider.System);
        _ = await manager.ProvisionAsync(WorkloadId, NewProvisionRequest(), ActorId, "employee-token");
        context.ChangeTracker.Clear();
        _ = await manager.RotateAsync(
            WorkloadId,
            new RotateServiceIdentityRequest { OperationId = Guid.NewGuid(), GracePeriodSeconds = 60 },
            ActorId);
        context.ChangeTracker.Clear();

        _ = await manager.RotateAsync(
            WorkloadId,
            new RotateServiceIdentityRequest { OperationId = Guid.NewGuid(), GracePeriodSeconds = 60 },
            ActorId);

        var states = await context.ServiceCredentialVersions.AsNoTracking()
            .OrderBy(item => item.Version)
            .Select(item => item.Status)
            .ToListAsync();
        Assert.Equal(
            [
                ServiceCredentialVersionStatus.Revoked,
                ServiceCredentialVersionStatus.Grace,
                ServiceCredentialVersionStatus.Active
            ],
            states);
    }

    [Fact]
    public async Task RevokeAsync_CredentialCommittedResume_CompletesWithoutDuplicateAudit()
    {
        await using var context = factory.CreateDbContext();
        var manager = new ServiceIdentityManager(context, new RecordingIamClient(), TimeProvider.System);
        _ = await manager.ProvisionAsync(WorkloadId, NewProvisionRequest(), ActorId, "employee-token");
        var operationId = Guid.NewGuid();
        context.ServiceIdentityOperations.Add(new ServiceIdentityOperation
        {
            Id = operationId,
            WorkloadId = WorkloadId,
            Kind = ServiceIdentityOperationKind.Revoke,
            RequestHash = HashCanonicalRequest($"revoke|{WorkloadId}"),
            ActorId = ActorId,
            State = ServiceIdentityOperationState.CredentialCommitted,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        });
        await context.SaveChangesAsync();
        var auditCount = await context.AuthAuditLogs.CountAsync();
        context.ChangeTracker.Clear();

        await manager.RevokeAsync(
            WorkloadId,
            new RevokeServiceIdentityRequest { OperationId = operationId },
            ActorId);

        Assert.Equal(auditCount, await context.AuthAuditLogs.CountAsync());
        Assert.Equal(
            ServiceIdentityOperationState.Completed,
            await context.ServiceIdentityOperations.AsNoTracking()
                .Where(item => item.Id == operationId)
                .Select(item => item.State)
                .SingleAsync());
    }

    private static ProvisionServiceIdentityRequest NewProvisionRequest() => new()
    {
        OperationId = Guid.NewGuid(),
        ProfileVersion = 1,
        ServiceName = "Auth Service",
        HardExpiryDays = 30
    };

    private static string HashCanonicalRequest(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string Hash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static async Task<string> DumpStringColumnsAsync(Maliev.AuthService.Infrastructure.DbContexts.AuthDbContext context)
    {
        var credential = await context.ServiceCredentials.AsNoTracking().SingleAsync(item => item.WorkloadId == WorkloadId);
        var operation = await context.ServiceIdentityOperations.AsNoTracking().SingleAsync();
        return string.Join('|',
            credential.ClientId,
            credential.ClientSecretHash,
            credential.ServiceName,
            credential.WorkloadId,
            credential.RoleId,
            operation.RequestHash,
            operation.IamRoleId);
    }

    private sealed class RecordingIamClient : IWorkloadIdentityIamClient
    {
        public int CallCount { get; private set; }

        public string? LastBearerToken { get; private set; }

        public WorkloadPrincipalResponse Response { get; init; } = new()
        {
            WorkloadId = WorkloadId,
            PrincipalId = Guid.Parse("11111111-1111-1111-1111-111111111111"),
            ProfileVersion = 1,
            RoleId = ExpectedRoleId
        };

        public bool ThrowOnCall { get; init; }

        public Task<WorkloadPrincipalResponse> ProvisionAsync(
            string workloadId,
            ProvisionWorkloadPrincipalRequest request,
            string callerBearerToken,
            CancellationToken cancellationToken = default)
        {
            CallCount++;
            if (ThrowOnCall)
            {
                throw new InvalidOperationException("IAM must not be called for an IamReady resume");
            }

            LastBearerToken = callerBearerToken;
            return Task.FromResult(Response);
        }
    }
}
