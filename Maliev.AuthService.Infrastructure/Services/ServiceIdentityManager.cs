using System.Data;
using System.Security.Cryptography;
using System.Text;
using Maliev.AuthService.Application.DTOs.IAM;
using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Application.DTOs.Response;
using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Domain.Entities;
using Maliev.AuthService.Infrastructure.DbContexts;
using Microsoft.EntityFrameworkCore;

namespace Maliev.AuthService.Infrastructure.Services;

/// <summary>Coordinates IAM-backed service identity credential lifecycle operations.</summary>
public sealed class ServiceIdentityManager(
    AuthDbContext dbContext,
    IWorkloadIdentityIamClient iamClient,
    TimeProvider timeProvider) : IServiceIdentityManager
{
    /// <inheritdoc/>
    public async Task<ServiceIdentityResponse> ProvisionAsync(
        string workloadId,
        ProvisionServiceIdentityRequest request,
        Guid actorId,
        string callerBearerToken,
        CancellationToken cancellationToken = default)
    {
        workloadId = ValidateWorkloadId(workloadId);
        ValidateActorAndOperation(actorId, request.OperationId);
        var requestHash = HashCanonicalRequest(
            $"provision|{workloadId}|{request.ProfileVersion}|{request.ServiceName}|{request.HardExpiryDays}");

        return await WithWorkloadLockAsync(workloadId, async () =>
        {
            var operation = await GetOrStartOperationAsync(
                request.OperationId,
                workloadId,
                ServiceIdentityOperationKind.Provision,
                requestHash,
                actorId,
                cancellationToken);

            if (operation.State == ServiceIdentityOperationState.Completed)
            {
                return await GetRequiredResponseAsync(workloadId, secret: null, cancellationToken);
            }

            if (operation.State == ServiceIdentityOperationState.Started)
            {
                var iamResponse = await iamClient.ProvisionAsync(
                    workloadId,
                    new ProvisionWorkloadPrincipalRequest
                    {
                        ProfileVersion = request.ProfileVersion,
                        OperationId = request.OperationId
                    },
                    callerBearerToken,
                    cancellationToken);
                ValidateIamResponse(workloadId, request.ProfileVersion, iamResponse);
                operation.IamPrincipalId = iamResponse.PrincipalId;
                operation.IamProfileVersion = iamResponse.ProfileVersion;
                operation.IamRoleId = iamResponse.RoleId;
                operation.State = ServiceIdentityOperationState.IamReady;
                operation.UpdatedAt = UtcNow;
                await dbContext.SaveChangesAsync(cancellationToken);
            }

            if (operation.State == ServiceIdentityOperationState.CredentialCommitted)
            {
                await CompleteAsync(operation, cancellationToken);
                return await GetRequiredResponseAsync(workloadId, secret: null, cancellationToken);
            }

            var existing = await dbContext.ServiceCredentials
                .AsNoTracking()
                .Include(item => item.Versions)
                .SingleOrDefaultAsync(credential => credential.WorkloadId == workloadId, cancellationToken);
            if (existing is not null)
            {
                EnsureExactBinding(existing, operation);
                EnsureProvisionMatches(existing, request);
                operation.State = ServiceIdentityOperationState.CredentialCommitted;
                operation.UpdatedAt = UtcNow;
                await dbContext.SaveChangesAsync(cancellationToken);
                await CompleteAsync(operation, cancellationToken);
                return await GetRequiredResponseAsync(workloadId, secret: null, cancellationToken);
            }

            var generatedSecret = GenerateSecret();
            var secretHash = HashSecret(generatedSecret);
            var now = UtcNow;
            var credential = new ServiceCredential
            {
                Id = Guid.NewGuid(),
                ClientId = $"service-{workloadId}",
                PrincipalId = operation.IamPrincipalId,
                WorkloadId = workloadId,
                ProfileVersion = operation.IamProfileVersion,
                RoleId = operation.IamRoleId,
                ClientSecretHash = secretHash,
                ServiceName = request.ServiceName.Trim(),
                IsActive = true,
                CreatedAt = now.UtcDateTime,
                UpdatedAt = now.UtcDateTime
            };
            var version = new ServiceCredentialVersion
            {
                Id = Guid.NewGuid(),
                ServiceCredentialId = credential.Id,
                Version = 1,
                SecretHash = secretHash,
                Status = ServiceCredentialVersionStatus.Active,
                CreatedAt = now,
                ActivatedAt = now,
                HardExpiresAt = now.AddDays(request.HardExpiryDays)
            };

            await using (var transaction = await dbContext.Database.BeginTransactionAsync(cancellationToken))
            {
                dbContext.ServiceCredentials.Add(credential);
                dbContext.ServiceCredentialVersions.Add(version);
                AddAudit(actorId, "service_identity_provision", request.OperationId);
                operation.CredentialVersionId = version.Id;
                operation.State = ServiceIdentityOperationState.CredentialCommitted;
                operation.UpdatedAt = now;
                await dbContext.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
            }

            await CompleteAsync(operation, cancellationToken);
            return BuildResponse(credential, version, generatedSecret);
        }, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<ServiceIdentityResponse?> GetAsync(
        string workloadId,
        CancellationToken cancellationToken = default)
    {
        workloadId = ValidateWorkloadId(workloadId);
        var credential = await dbContext.ServiceCredentials
            .AsNoTracking()
            .Include(entity => entity.Versions)
            .SingleOrDefaultAsync(entity => entity.WorkloadId == workloadId, cancellationToken);
        if (credential is null)
        {
            return null;
        }

        var version = credential.Versions
            .OrderByDescending(item => item.Version)
            .FirstOrDefault()
            ?? throw new ServiceIdentityConflictException("Managed identity has no credential version");
        return BuildResponse(credential, version, secret: null);
    }

    /// <inheritdoc/>
    public async Task<ServiceIdentityResponse> RotateAsync(
        string workloadId,
        RotateServiceIdentityRequest request,
        Guid actorId,
        CancellationToken cancellationToken = default)
    {
        workloadId = ValidateWorkloadId(workloadId);
        ValidateActorAndOperation(actorId, request.OperationId);
        var requestHash = HashCanonicalRequest(
            $"rotate|{workloadId}|{request.GracePeriodSeconds}|{request.HardExpiryDays}");

        return await WithWorkloadLockAsync(workloadId, async () =>
        {
            var operation = await GetOrStartOperationAsync(
                request.OperationId,
                workloadId,
                ServiceIdentityOperationKind.Rotate,
                requestHash,
                actorId,
                cancellationToken);
            if (operation.State is ServiceIdentityOperationState.Completed or ServiceIdentityOperationState.CredentialCommitted)
            {
                if (operation.State == ServiceIdentityOperationState.CredentialCommitted)
                {
                    await CompleteAsync(operation, cancellationToken);
                }

                return await GetRequiredResponseAsync(workloadId, secret: null, cancellationToken);
            }

            var credential = await dbContext.ServiceCredentials
                .Include(entity => entity.Versions)
                .SingleOrDefaultAsync(entity => entity.WorkloadId == workloadId, cancellationToken)
                ?? throw new ServiceIdentityNotFoundException();
            EnsureManagedActive(credential);

            if (operation.State == ServiceIdentityOperationState.Started)
            {
                operation.IamPrincipalId = credential.PrincipalId;
                operation.IamProfileVersion = credential.ProfileVersion;
                operation.IamRoleId = credential.RoleId;
                operation.State = ServiceIdentityOperationState.IamReady;
                operation.UpdatedAt = UtcNow;
                await dbContext.SaveChangesAsync(cancellationToken);
            }

            var generatedSecret = GenerateSecret();
            var now = UtcNow;
            var version = new ServiceCredentialVersion
            {
                Id = Guid.NewGuid(),
                ServiceCredentialId = credential.Id,
                Version = credential.Versions.Select(item => item.Version).DefaultIfEmpty().Max() + 1,
                SecretHash = HashSecret(generatedSecret),
                Status = ServiceCredentialVersionStatus.Active,
                CreatedAt = now,
                ActivatedAt = now,
                HardExpiresAt = now.AddDays(request.HardExpiryDays)
            };
            credential.ClientSecretHash = version.SecretHash;
            credential.UpdatedAt = now.UtcDateTime;
            foreach (var trackedVersion in credential.Versions)
            {
                dbContext.Entry(trackedVersion).State = EntityState.Detached;
            }

            await using (var transaction = await dbContext.Database.BeginTransactionAsync(cancellationToken))
            {
                if (request.GracePeriodSeconds == 0)
                {
                    await dbContext.ServiceCredentialVersions
                        .Where(item =>
                            item.ServiceCredentialId == credential.Id &&
                            (item.Status == ServiceCredentialVersionStatus.Active ||
                                item.Status == ServiceCredentialVersionStatus.Grace))
                        .ExecuteUpdateAsync(setters => setters
                            .SetProperty(item => item.Status, ServiceCredentialVersionStatus.Revoked)
                            .SetProperty(item => item.RevokedAt, now), cancellationToken);
                }
                else
                {
                    await dbContext.ServiceCredentialVersions
                        .Where(item =>
                            item.ServiceCredentialId == credential.Id &&
                            item.Status == ServiceCredentialVersionStatus.Grace)
                        .ExecuteUpdateAsync(setters => setters
                            .SetProperty(item => item.Status, ServiceCredentialVersionStatus.Revoked)
                            .SetProperty(item => item.RevokedAt, now), cancellationToken);
                    var graceExpiresAt = now.AddSeconds(request.GracePeriodSeconds);
                    await dbContext.ServiceCredentialVersions
                        .Where(item =>
                            item.ServiceCredentialId == credential.Id &&
                            item.Status == ServiceCredentialVersionStatus.Active)
                        .ExecuteUpdateAsync(setters => setters
                            .SetProperty(item => item.Status, ServiceCredentialVersionStatus.Grace)
                            .SetProperty(item => item.GraceExpiresAt, graceExpiresAt), cancellationToken);
                }

                dbContext.ServiceCredentialVersions.Add(version);
                AddAudit(actorId, "service_identity_rotate", request.OperationId);
                operation.CredentialVersionId = version.Id;
                operation.State = ServiceIdentityOperationState.CredentialCommitted;
                operation.UpdatedAt = now;
                await dbContext.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
            }

            await CompleteAsync(operation, cancellationToken);
            return BuildResponse(credential, version, generatedSecret);
        }, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task RevokeAsync(
        string workloadId,
        RevokeServiceIdentityRequest request,
        Guid actorId,
        CancellationToken cancellationToken = default)
    {
        workloadId = ValidateWorkloadId(workloadId);
        ValidateActorAndOperation(actorId, request.OperationId);
        var requestHash = HashCanonicalRequest($"revoke|{workloadId}");

        await WithWorkloadLockAsync(workloadId, async () =>
        {
            var operation = await GetOrStartOperationAsync(
                request.OperationId,
                workloadId,
                ServiceIdentityOperationKind.Revoke,
                requestHash,
                actorId,
                cancellationToken);
            if (operation.State == ServiceIdentityOperationState.Completed)
            {
                return true;
            }

            if (operation.State == ServiceIdentityOperationState.CredentialCommitted)
            {
                await CompleteAsync(operation, cancellationToken);
                return true;
            }

            var credential = await dbContext.ServiceCredentials
                .Include(entity => entity.Versions)
                .SingleOrDefaultAsync(entity => entity.WorkloadId == workloadId, cancellationToken)
                ?? throw new ServiceIdentityNotFoundException();
            var now = UtcNow;
            operation.IamPrincipalId ??= credential.PrincipalId;
            operation.IamProfileVersion ??= credential.ProfileVersion;
            operation.IamRoleId ??= credential.RoleId;
            operation.State = ServiceIdentityOperationState.IamReady;
            credential.IsActive = false;
            credential.ClientSecretHash = HashSecret(GenerateSecret());
            credential.RevokedAt = now;
            credential.UpdatedAt = now.UtcDateTime;
            foreach (var trackedVersion in credential.Versions)
            {
                dbContext.Entry(trackedVersion).State = EntityState.Detached;
            }

            await using (var transaction = await dbContext.Database.BeginTransactionAsync(cancellationToken))
            {
                await dbContext.ServiceCredentialVersions
                    .Where(item =>
                        item.ServiceCredentialId == credential.Id &&
                        item.Status != ServiceCredentialVersionStatus.Revoked)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(item => item.Status, ServiceCredentialVersionStatus.Revoked)
                        .SetProperty(item => item.RevokedAt, now), cancellationToken);
                AddAudit(actorId, "service_identity_revoke", request.OperationId);
                operation.State = ServiceIdentityOperationState.CredentialCommitted;
                operation.UpdatedAt = now;
                await dbContext.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
            }

            await CompleteAsync(operation, cancellationToken);
            return true;
        }, cancellationToken);
    }

    private DateTimeOffset UtcNow => timeProvider.GetUtcNow();

    private async Task<ServiceIdentityOperation> GetOrStartOperationAsync(
        Guid operationId,
        string workloadId,
        ServiceIdentityOperationKind kind,
        string requestHash,
        Guid actorId,
        CancellationToken cancellationToken)
    {
        var operation = await dbContext.ServiceIdentityOperations
            .SingleOrDefaultAsync(item => item.Id == operationId, cancellationToken);
        if (operation is not null)
        {
            if (operation.WorkloadId != workloadId ||
                operation.Kind != kind ||
                operation.RequestHash != requestHash ||
                operation.ActorId != actorId)
            {
                throw new ServiceIdentityConflictException(
                    "Operation identifier is already bound to another actor or request");
            }

            return operation;
        }

        var now = UtcNow;
        operation = new ServiceIdentityOperation
        {
            Id = operationId,
            WorkloadId = workloadId,
            Kind = kind,
            RequestHash = requestHash,
            ActorId = actorId,
            State = ServiceIdentityOperationState.Started,
            CreatedAt = now,
            UpdatedAt = now
        };
        dbContext.ServiceIdentityOperations.Add(operation);
        await dbContext.SaveChangesAsync(cancellationToken);
        return operation;
    }

    private async Task CompleteAsync(
        ServiceIdentityOperation operation,
        CancellationToken cancellationToken)
    {
        operation.State = ServiceIdentityOperationState.Completed;
        operation.UpdatedAt = UtcNow;
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    private async Task<ServiceIdentityResponse> GetRequiredResponseAsync(
        string workloadId,
        string? secret,
        CancellationToken cancellationToken) =>
        await GetAsync(workloadId, cancellationToken)
        ?? throw new ServiceIdentityConflictException("Completed operation has no credential");

    private void AddAudit(Guid actorId, string action, Guid operationId)
    {
        dbContext.AuthAuditLogs.Add(new AuthAuditLog
        {
            Id = Guid.NewGuid(),
            UserId = actorId,
            UserType = UserType.Employee,
            Action = action,
            IpAddress = string.Empty,
            Success = true,
            CorrelationId = operationId.ToString("D"),
            CreatedAt = UtcNow.UtcDateTime
        });
    }

    private static void ValidateIamResponse(
        string workloadId,
        int profileVersion,
        WorkloadPrincipalResponse response)
    {
        if (response.WorkloadId != workloadId ||
            response.PrincipalId == Guid.Empty ||
            response.ProfileVersion != profileVersion ||
            !IsCanonicalRole(response.RoleId) ||
            response.RoleId.Contains("platform.owner", StringComparison.Ordinal))
        {
            throw new ServiceIdentityConflictException("IAM returned a mismatched or unsafe workload binding");
        }
    }

    private static void EnsureExactBinding(
        ServiceCredential credential,
        ServiceIdentityOperation operation)
    {
        if (credential.PrincipalId != operation.IamPrincipalId ||
            credential.ProfileVersion != operation.IamProfileVersion ||
            credential.RoleId != operation.IamRoleId)
        {
            throw new ServiceIdentityConflictException("Existing service identity has another IAM binding");
        }
    }

    private static void EnsureManagedActive(ServiceCredential credential)
    {
        if (!credential.IsActive || credential.RevokedAt.HasValue ||
            !credential.PrincipalId.HasValue || credential.PrincipalId == Guid.Empty ||
            !credential.ProfileVersion.HasValue || string.IsNullOrWhiteSpace(credential.RoleId))
        {
            throw new ServiceIdentityConflictException("Service identity is not an active managed identity");
        }
    }

    private static void EnsureProvisionMatches(
        ServiceCredential credential,
        ProvisionServiceIdentityRequest request)
    {
        var latest = credential.Versions.OrderByDescending(item => item.Version).FirstOrDefault()
            ?? throw new ServiceIdentityConflictException("Existing service identity has no credential version");
        var configuredLifetime = latest.HardExpiresAt - latest.CreatedAt;
        if (credential.ServiceName != request.ServiceName.Trim() ||
            configuredLifetime != TimeSpan.FromDays(request.HardExpiryDays))
        {
            throw new ServiceIdentityConflictException(
                "Existing service identity does not match the requested lifecycle parameters");
        }
    }

    private static ServiceIdentityResponse BuildResponse(
        ServiceCredential credential,
        ServiceCredentialVersion version,
        string? secret) => new()
        {
            WorkloadId = credential.WorkloadId
                ?? throw new ServiceIdentityConflictException("Credential is not workload managed"),
            ClientId = credential.ClientId,
            PrincipalId = credential.PrincipalId
                ?? throw new ServiceIdentityConflictException("Credential has no IAM principal"),
            ProfileVersion = credential.ProfileVersion
                ?? throw new ServiceIdentityConflictException("Credential has no IAM profile"),
            RoleId = credential.RoleId
                ?? throw new ServiceIdentityConflictException("Credential has no IAM role"),
            IsActive = credential.IsActive,
            CredentialVersion = version.Version,
            ClientSecret = secret,
            SecretRetrievable = secret is not null,
            HardExpiresAt = version.HardExpiresAt
        };

    private static string ValidateWorkloadId(string workloadId)
    {
        if (workloadId is not { Length: > 0 and <= 80 } ||
            workloadId != workloadId.Trim().ToLowerInvariant() ||
            workloadId[0] is not (>= 'a' and <= 'z') ||
            workloadId.Any(character => character is not (
                >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '.')))
        {
            throw new ArgumentException("Workload identifier is not canonical", nameof(workloadId));
        }

        return workloadId;
    }

    private static void ValidateActorAndOperation(Guid actorId, Guid operationId)
    {
        ArgumentOutOfRangeException.ThrowIfEqual(actorId, Guid.Empty);
        ArgumentOutOfRangeException.ThrowIfEqual(operationId, Guid.Empty);
    }

    private static bool IsCanonicalRole(string value) =>
        value is { Length: > 0 and <= 160 } &&
        value == value.Trim().ToLowerInvariant() &&
        value != "*" &&
        !value.Contains('*') &&
        value.All(character => character is
            >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_' or '.' or '/');

    private static string GenerateSecret()
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string HashSecret(string secret) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));

    private static string HashCanonicalRequest(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private async Task<T> WithWorkloadLockAsync<T>(
        string workloadId,
        Func<Task<T>> action,
        CancellationToken cancellationToken)
    {
        var connection = dbContext.Database.GetDbConnection();
        var closeConnection = connection.State == ConnectionState.Closed;
        if (closeConnection)
        {
            await dbContext.Database.OpenConnectionAsync(cancellationToken);
        }

        await dbContext.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_lock(hashtextextended({workloadId}, 0));",
            cancellationToken);
        try
        {
            return await action();
        }
        finally
        {
            await dbContext.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT pg_advisory_unlock(hashtextextended({workloadId}, 0));",
                CancellationToken.None);
            if (closeConnection)
            {
                await dbContext.Database.CloseConnectionAsync();
            }
        }
    }
}

/// <summary>Signals an idempotency or authoritative binding conflict.</summary>
public sealed class ServiceIdentityConflictException(string message) : InvalidOperationException(message);

/// <summary>Signals that a managed service identity was not found.</summary>
public sealed class ServiceIdentityNotFoundException : KeyNotFoundException;
