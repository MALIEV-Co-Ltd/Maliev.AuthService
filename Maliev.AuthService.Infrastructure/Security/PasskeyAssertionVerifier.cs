using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Maliev.AuthService.Infrastructure.Security;

/// <summary>
/// Applies MALIEV's exact-origin and authenticator-state policy around the FIDO2 verifier.
/// </summary>
public sealed class PasskeyAssertionVerifier(
    IFido2 fido2,
    IOptions<PasskeyWebAuthnOptions> options,
    ILogger<PasskeyAssertionVerifier> logger) : IPasskeyAssertionVerifier
{
    private const byte UserPresent = 0x01;
    private const byte UserVerified = 0x04;
    private const byte BackupEligible = 0x08;
    private const byte BackupState = 0x10;
    private const byte AllowedFlags = UserPresent | UserVerified | BackupEligible | BackupState;
    private readonly PasskeyWebAuthnOptions _options = options.Value;

    /// <inheritdoc />
    public async Task<PasskeyAssertionVerificationResult> VerifyAsync(
        PasskeyAssertionVerificationInput input,
        CancellationToken cancellationToken)
    {
        if (input.StoredCredentialId is not { Length: >= 1 and <= 1024 } ||
            input.StoredPublicKeyCose is not { Length: >= 1 and <= 4096 })
        {
            return PasskeyAssertionVerificationResult.Failed(PasskeyAssertionFailure.InvalidCredential);
        }

        if (input.StoredUserHandle is not { Length: >= 1 and <= 64 })
        {
            return PasskeyAssertionVerificationResult.Failed(PasskeyAssertionFailure.InvalidUserHandle);
        }

        if (!TryDecodeCanonicalBase64Url(input.CredentialId, 1, 1024, out var credentialId) ||
            !TryDecodeCanonicalBase64Url(input.AuthenticatorData, 37, 4096, out var authenticatorData) ||
            !TryDecodeCanonicalBase64Url(input.ClientDataJson, 2, 8192, out var clientDataJson) ||
            !TryDecodeCanonicalBase64Url(input.Signature, 1, 2048, out var signature))
        {
            return PasskeyAssertionVerificationResult.Failed(PasskeyAssertionFailure.InvalidEncoding);
        }

        if (string.IsNullOrWhiteSpace(input.UserHandle))
        {
            return PasskeyAssertionVerificationResult.Failed(PasskeyAssertionFailure.InvalidUserHandle);
        }

        if (!TryDecodeCanonicalBase64Url(input.UserHandle, 1, 64, out var userHandle))
        {
            return PasskeyAssertionVerificationResult.Failed(PasskeyAssertionFailure.InvalidEncoding);
        }

        if (!FixedTimeEquals(credentialId, input.StoredCredentialId))
        {
            return PasskeyAssertionVerificationResult.Failed(PasskeyAssertionFailure.InvalidCredential);
        }

        if (!FixedTimeEquals(userHandle, input.StoredUserHandle))
        {
            return PasskeyAssertionVerificationResult.Failed(PasskeyAssertionFailure.InvalidUserHandle);
        }

        if (!TryReadAndValidateOptions(input.AssertionOptionsJson, out var assertionOptions))
        {
            return PasskeyAssertionVerificationResult.Failed(PasskeyAssertionFailure.InvalidOptions);
        }

        var clientDataFailure = ValidateClientData(clientDataJson, assertionOptions!.Challenge);
        if (clientDataFailure != PasskeyAssertionFailure.None)
        {
            return PasskeyAssertionVerificationResult.Failed(clientDataFailure);
        }

        var stateFailure = ValidateAuthenticatorState(
            authenticatorData,
            input.StoredSignCount,
            input.StoredBackupEligible);
        if (stateFailure != PasskeyAssertionFailure.None)
        {
            return PasskeyAssertionVerificationResult.Failed(stateFailure);
        }

        try
        {
            var response = new AuthenticatorAssertionRawResponse
            {
                Id = input.CredentialId,
                RawId = credentialId,
                Type = PublicKeyCredentialType.PublicKey,
                ClientExtensionResults = new AuthenticationExtensionsClientOutputs(),
                Response = new AuthenticatorAssertionRawResponse.AssertionResponse
                {
                    AuthenticatorData = authenticatorData,
                    ClientDataJson = clientDataJson,
                    Signature = signature,
                    UserHandle = userHandle
                }
            };
            IsUserHandleOwnerOfCredentialIdAsync ownsCredential = (parameters, _) =>
                Task.FromResult(
                    FixedTimeEquals(parameters.CredentialId, input.StoredCredentialId) &&
                    FixedTimeEquals(parameters.UserHandle, input.StoredUserHandle));
            var result = await fido2.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = response,
                OriginalOptions = assertionOptions,
                StoredPublicKey = input.StoredPublicKeyCose,
                StoredSignatureCounter = input.StoredSignCount,
                IsUserHandleOwnerOfCredentialIdCallback = ownsCredential
            }, cancellationToken: cancellationToken);

            return new PasskeyAssertionVerificationResult(
                true,
                result.SignCount,
                result.IsBackedUp,
                PasskeyAssertionFailure.None);
        }
        catch (Fido2VerificationException exception)
        {
            logger.LogWarning(
                "Passkey assertion rejected by FIDO2 verifier with category {FailureCategory}",
                exception.Code);
            return PasskeyAssertionVerificationResult.Failed(PasskeyAssertionFailure.VerificationFailed);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            logger.LogWarning(
                "Passkey assertion failed closed with exception type {ExceptionType}",
                exception.GetType().Name);
            return PasskeyAssertionVerificationResult.Failed(PasskeyAssertionFailure.VerificationFailed);
        }
    }

    private bool TryReadAndValidateOptions(string json, out AssertionOptions? assertionOptions)
    {
        assertionOptions = null;
        if (string.IsNullOrWhiteSpace(json) || json.Length > 16_384)
        {
            return false;
        }

        try
        {
            assertionOptions = AssertionOptions.FromJson(json);
            return assertionOptions is not null &&
                assertionOptions.Challenge is { Length: >= 32 and <= 64 } &&
                _options.AllowedOrigins is { Count: > 0 } &&
                string.Equals(assertionOptions.RpId, _options.RpId, StringComparison.Ordinal) &&
                assertionOptions.UserVerification == UserVerificationRequirement.Required &&
                assertionOptions.AllowCredentials.Count == 0 &&
                assertionOptions.Extensions is null;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private PasskeyAssertionFailure ValidateClientData(byte[] clientDataJson, byte[] expectedChallenge)
    {
        try
        {
            using var document = JsonDocument.Parse(clientDataJson, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 8
            });
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                HasDuplicateProperties(document.RootElement) ||
                !TryGetRequiredString(document.RootElement, "type", out var type) ||
                !string.Equals(type, "webauthn.get", StringComparison.Ordinal) ||
                !TryGetRequiredString(document.RootElement, "challenge", out var challenge) ||
                !TryDecodeCanonicalBase64Url(challenge, 32, 64, out var challengeBytes) ||
                !FixedTimeEquals(challengeBytes, expectedChallenge))
            {
                return PasskeyAssertionFailure.InvalidClientData;
            }

            if (!TryGetRequiredString(document.RootElement, "origin", out var origin) ||
                !_options.AllowedOrigins.Contains(origin, StringComparer.Ordinal))
            {
                return PasskeyAssertionFailure.InvalidOrigin;
            }

            if (document.RootElement.TryGetProperty("topOrigin", out _) ||
                document.RootElement.TryGetProperty("crossOrigin", out var crossOrigin) &&
                (crossOrigin.ValueKind != JsonValueKind.False))
            {
                return PasskeyAssertionFailure.CrossOriginNotAllowed;
            }

            return PasskeyAssertionFailure.None;
        }
        catch (JsonException)
        {
            return PasskeyAssertionFailure.InvalidClientData;
        }
    }

    private static PasskeyAssertionFailure ValidateAuthenticatorState(
        byte[] authenticatorData,
        uint storedSignCount,
        bool storedBackupEligible)
    {
        var flags = authenticatorData[32];
        if ((flags & ~AllowedFlags) != 0 ||
            (flags & (UserPresent | UserVerified)) != (UserPresent | UserVerified) ||
            (flags & BackupState) != 0 && (flags & BackupEligible) == 0)
        {
            return PasskeyAssertionFailure.InvalidAuthenticatorFlags;
        }

        var backupEligible = (flags & BackupEligible) != 0;
        if (backupEligible != storedBackupEligible)
        {
            return PasskeyAssertionFailure.BackupEligibilityChanged;
        }

        var signCount = BinaryPrimitives.ReadUInt32BigEndian(authenticatorData.AsSpan(33, 4));
        if (storedSignCount > 0 && signCount == 0 ||
            signCount > 0 && signCount <= storedSignCount)
        {
            return PasskeyAssertionFailure.InvalidSignCount;
        }

        return PasskeyAssertionFailure.None;
    }

    private static bool TryDecodeCanonicalBase64Url(
        string? value,
        int minimumBytes,
        int maximumBytes,
        out byte[] decoded)
    {
        decoded = [];
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > ((maximumBytes + 2) / 3 * 4) ||
            value.Contains('=') ||
            value.Contains('+') ||
            value.Contains('/') ||
            value.Any(character =>
                !(character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_')))
        {
            return false;
        }

        try
        {
            var padded = value.Replace('-', '+').Replace('_', '/');
            padded += new string('=', (4 - padded.Length % 4) % 4);
            decoded = Convert.FromBase64String(padded);
            return decoded.Length >= minimumBytes &&
                decoded.Length <= maximumBytes &&
                string.Equals(ToBase64Url(decoded), value, StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            decoded = [];
            return false;
        }
    }

    private static bool HasDuplicateProperties(JsonElement element)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        return element.EnumerateObject().Any(property => !names.Add(property.Name));
    }

    private static bool TryGetRequiredString(JsonElement element, string propertyName, out string value)
    {
        value = string.Empty;
        if (!element.TryGetProperty(propertyName, out var property) ||
            property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = property.GetString() ?? string.Empty;
        return value.Length > 0;
    }

    private static bool FixedTimeEquals(byte[] left, byte[] right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static string ToBase64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
