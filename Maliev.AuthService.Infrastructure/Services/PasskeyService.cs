using Fido2NetLib;
using Fido2NetLib.Objects;
using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Application.DTOs.Response;
using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Domain.Entities;
using Maliev.AuthService.Infrastructure.DbContexts;
using Maliev.AuthService.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Maliev.AuthService.Infrastructure.Services;

/// <summary>
/// Orchestrates caller-bound, single-use WebAuthn passkey authentication.
/// </summary>
public sealed class PasskeyService(
    AuthDbContext dbContext,
    IPasskeyCeremonyStore ceremonyStore,
    IPasskeyAssertionVerifier assertionVerifier,
    IFido2 fido2,
    IOptions<PasskeyWebAuthnOptions> options,
    TimeProvider timeProvider,
    ILogger<PasskeyService> logger) : IPasskeyService
{
    private const int VerifiedRegistrationVersion = 1;
    private readonly PasskeyWebAuthnOptions _options = options.Value;

    /// <inheritdoc />
    public async Task<PasskeyAuthBeginResponse?> BeginAuthenticationAsync(
        PasskeyAuthBeginRequest request,
        string serviceName,
        CancellationToken ct)
    {
        if (!_options.Enabled ||
            request.PrincipalId.HasValue ||
            string.IsNullOrWhiteSpace(request.Application) ||
            string.IsNullOrWhiteSpace(serviceName) ||
            !TryResolveBinding(
                request.Application,
                serviceName,
                out var application,
                out var expectedUserType))
        {
            return null;
        }

        var assertionOptions = fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = [],
            UserVerification = UserVerificationRequirement.Required,
            Extensions = null
        });
        PasskeyCeremonyIssue issued;
        try
        {
            issued = await ceremonyStore.IssueAsync(
                serviceName,
                application,
                expectedUserType,
                assertionOptions.ToJson(),
                assertionOptions.Challenge,
                ct);
        }
        catch (PasskeyCeremonyCapacityExceededException)
        {
            logger.LogWarning(
                "Rejected passkey ceremony because the outstanding quota was reached for application {Application}",
                application);
            return null;
        }

        logger.LogInformation(
            "Issued passkey assertion ceremony for application {Application}",
            application);
        return new PasskeyAuthBeginResponse(
            issued.FlowId,
            issued.ExpiresAtUtc,
            assertionOptions.RpId ?? _options.RpId,
            ToBase64Url(assertionOptions.Challenge),
            [],
            "required",
            assertionOptions.Timeout);
    }

    /// <inheritdoc />
    public async Task<PasskeyAuthCompleteResponse> CompleteAuthenticationAsync(
        PasskeyAuthCompleteRequest request,
        string serviceName,
        CancellationToken ct)
    {
        if (!_options.Enabled)
        {
            return Failed("passkey_unavailable");
        }

        if (!TryResolveBinding(
                request.Application,
                serviceName,
                out var application,
                out _))
        {
            return Failed("passkey_identity_invalid");
        }

        var ceremony = await ceremonyStore.ConsumeAsync(
            request.FlowId,
            serviceName,
            application,
            ct);
        if (ceremony is null)
        {
            logger.LogWarning(
                "Rejected missing, expired, replayed, or caller-mismatched passkey ceremony for application {Application}",
                NormalizeForLog(request.Application));
            return Failed("passkey_identity_invalid");
        }

        if (string.IsNullOrWhiteSpace(request.CredentialId) || request.CredentialId.Length > 1366)
        {
            return Failed("passkey_identity_invalid");
        }

        for (var attempt = 0; attempt < 2; attempt++)
        {
            var credential = await FindVerifiedCredentialAsync(request.CredentialId, ct);
            if (credential is null ||
                !TryDecodeCanonicalBase64Url(credential.CredentialId, out var storedCredentialId))
            {
                return Failed("passkey_identity_invalid");
            }

            var principal = await dbContext.UserPrincipals
                .AsNoTracking()
                .Where(candidate =>
                    candidate.Id == credential.PrincipalId &&
                    candidate.UserType == ceremony.ExpectedUserType)
                .Select(candidate => new { candidate.Id, candidate.Email })
                .SingleOrDefaultAsync(ct);
            if (principal is null)
            {
                return Failed("passkey_identity_invalid");
            }

            var verification = await assertionVerifier.VerifyAsync(
                new PasskeyAssertionVerificationInput(
                    ceremony.AssertionOptionsJson,
                    request.CredentialId,
                    request.AuthenticatorData,
                    request.ClientDataJson,
                    request.Signature,
                    request.UserHandle,
                    storedCredentialId,
                    credential.PublicKeyCose!,
                    credential.UserHandle!,
                    checked((uint)credential.VerifiedSignCount!.Value),
                    credential.IsBackupEligible!.Value),
                ct);
            if (!verification.Success)
            {
                logger.LogWarning(
                    "Passkey assertion failed with category {FailureCategory}",
                    verification.Failure);
                return Failed("passkey_identity_invalid");
            }

            credential.VerifiedSignCount = verification.SignCount;
            credential.IsBackedUp = verification.IsBackedUp;
            credential.LastUsedAtUtc = timeProvider.GetUtcNow().UtcDateTime;
            try
            {
                await dbContext.SaveChangesAsync(ct);
            }
            catch (DbUpdateConcurrencyException)
            {
                if (attempt == 0)
                {
                    dbContext.Entry(credential).State = EntityState.Detached;
                    continue;
                }

                logger.LogWarning("Passkey assertion state update failed due to concurrent credential use");
                return Failed("passkey_temporarily_unavailable");
            }

            logger.LogInformation("Passkey assertion completed successfully");
            return new PasskeyAuthCompleteResponse(true, null, principal.Id, principal.Email);
        }

        logger.LogWarning("Passkey assertion state update failed due to concurrent credential use");
        return Failed("passkey_temporarily_unavailable");
    }

    private Task<PasskeyCredential?> FindVerifiedCredentialAsync(
        string credentialId,
        CancellationToken cancellationToken) =>
        dbContext.PasskeyCredentials.SingleOrDefaultAsync(
            credential =>
                credential.CredentialId == credentialId &&
                credential.RegistrationVerificationVersion == VerifiedRegistrationVersion &&
                credential.PublicKeyCose != null &&
                credential.UserHandle != null &&
                credential.VerifiedSignCount != null &&
                credential.IsBackupEligible != null &&
                credential.IsBackedUp != null,
            cancellationToken);

    private static PasskeyAuthCompleteResponse Failed(string code) =>
        new(false, code, null, null);

    private bool TryResolveBinding(
        string? requestedApplication,
        string? serviceName,
        out string application,
        out UserType expectedUserType)
    {
        application = NormalizeForBoundary(requestedApplication);
        expectedUserType = default;
        if (application.Length == 0 || string.IsNullOrWhiteSpace(serviceName))
        {
            return false;
        }

        if (!_options.Bindings.TryGetValue(application, out var binding) ||
            binding is null ||
            !string.Equals(
                binding.ServiceName,
                serviceName.Trim(),
                StringComparison.OrdinalIgnoreCase) ||
            binding.PrincipalType is not (UserType.Customer or UserType.Employee))
        {
            return false;
        }

        expectedUserType = binding.PrincipalType;
        return true;
    }

    private static string NormalizeForLog(string? application)
    {
        if (string.IsNullOrWhiteSpace(application))
        {
            return "missing";
        }

        var normalized = application.Trim().ToLowerInvariant();
        return normalized.Length <= 64 &&
            normalized.All(character => character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-')
            ? normalized
            : "invalid";
    }

    private static string NormalizeForBoundary(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim().ToLowerInvariant();
        return normalized.Length <= 64 &&
            normalized.All(character =>
                character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-')
            ? normalized
            : string.Empty;
    }

    private static bool TryDecodeCanonicalBase64Url(string value, out byte[] decoded)
    {
        decoded = [];
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > 1366 ||
            value.Contains('=') ||
            value.Contains('+') ||
            value.Contains('/'))
        {
            return false;
        }

        try
        {
            var padded = value.Replace('-', '+').Replace('_', '/');
            padded += new string('=', (4 - padded.Length % 4) % 4);
            decoded = Convert.FromBase64String(padded);
            return decoded is { Length: >= 1 and <= 1024 } &&
                string.Equals(ToBase64Url(decoded), value, StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            decoded = [];
            return false;
        }
    }

    private static string ToBase64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
