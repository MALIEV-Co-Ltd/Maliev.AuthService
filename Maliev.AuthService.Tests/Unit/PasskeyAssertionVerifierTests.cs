using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Maliev.AuthService.Infrastructure.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

/// <summary>
/// Exercises MALIEV's policy wrapper around the standards-compliant FIDO2 assertion verifier.
/// </summary>
public sealed class PasskeyAssertionVerifierTests
{
    private const string RpId = "maliev.test";
    private const string Origin = "https://app.maliev.test";

    /// <summary>Verifies a correctly signed, user-verified assertion succeeds.</summary>
    [Fact]
    public async Task VerifyAsync_ValidEs256Assertion_ReturnsUpdatedAuthenticatorState()
    {
        using var assertion = TestAssertion.Create(signCount: 7);
        var verifier = CreateVerifier();

        var result = await verifier.VerifyAsync(assertion.Input, CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal((uint)7, result.SignCount);
        Assert.False(result.IsBackedUp);
    }

    /// <summary>Verifies origin matching is exact and rejects a URL the library would normalize.</summary>
    [Fact]
    public async Task VerifyAsync_OriginWithPath_IsRejectedBeforeLibraryNormalization()
    {
        using var assertion = TestAssertion.Create(origin: $"{Origin}/attacker-path");
        var verifier = CreateVerifier();

        var result = await verifier.VerifyAsync(assertion.Input, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(PasskeyAssertionFailure.InvalidOrigin, result.Failure);
    }

    /// <summary>Verifies cross-origin assertions are rejected even when the effective origin is allowed.</summary>
    [Fact]
    public async Task VerifyAsync_CrossOriginClientData_IsRejected()
    {
        using var assertion = TestAssertion.Create(crossOrigin: true);
        var verifier = CreateVerifier();

        var result = await verifier.VerifyAsync(assertion.Input, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(PasskeyAssertionFailure.CrossOriginNotAllowed, result.Failure);
    }

    /// <summary>Verifies unsolicited authenticator flags fail closed.</summary>
    [Theory]
    [InlineData(0x45)] // UP | UV | AT
    [InlineData(0x85)] // UP | UV | ED
    [InlineData(0x07)] // UP | reserved bit | UV
    public async Task VerifyAsync_UnsolicitedOrReservedAuthenticatorFlags_AreRejected(byte flags)
    {
        using var assertion = TestAssertion.Create(flags: flags);
        var verifier = CreateVerifier();

        var result = await verifier.VerifyAsync(assertion.Input, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(PasskeyAssertionFailure.InvalidAuthenticatorFlags, result.Failure);
    }

    /// <summary>Verifies a synced-passkey backup eligibility bit cannot change after registration.</summary>
    [Fact]
    public async Task VerifyAsync_BackupEligibilityChanged_IsRejected()
    {
        using var assertion = TestAssertion.Create(flags: 0x0D, storedBackupEligible: false);
        var verifier = CreateVerifier();

        var result = await verifier.VerifyAsync(assertion.Input, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(PasskeyAssertionFailure.BackupEligibilityChanged, result.Failure);
    }

    /// <summary>Verifies a positive stored counter cannot reset to zero.</summary>
    [Fact]
    public async Task VerifyAsync_PositiveStoredCounterResetToZero_IsRejected()
    {
        using var assertion = TestAssertion.Create(signCount: 0, storedSignCount: 6);
        var verifier = CreateVerifier();

        var result = await verifier.VerifyAsync(assertion.Input, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(PasskeyAssertionFailure.InvalidSignCount, result.Failure);
    }

    /// <summary>Verifies discoverable authentication always proves the stored user handle.</summary>
    [Fact]
    public async Task VerifyAsync_MissingUserHandle_IsRejected()
    {
        using var assertion = TestAssertion.Create(includeUserHandle: false);
        var verifier = CreateVerifier();

        var result = await verifier.VerifyAsync(assertion.Input, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(PasskeyAssertionFailure.InvalidUserHandle, result.Failure);
    }

    /// <summary>Verifies signed browser data must contain the issued challenge and WebAuthn get type.</summary>
    [Theory]
    [InlineData(true, "webauthn.get")]
    [InlineData(false, "webauthn.create")]
    public async Task VerifyAsync_WrongChallengeOrType_IsRejected(bool useWrongChallenge, string type)
    {
        using var assertion = TestAssertion.Create(useWrongChallenge: useWrongChallenge, type: type);
        var verifier = CreateVerifier();

        var result = await verifier.VerifyAsync(assertion.Input, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(PasskeyAssertionFailure.InvalidClientData, result.Failure);
    }

    /// <summary>Verifies an embedded top origin is rejected because MALIEV does not allow embedded ceremonies.</summary>
    [Fact]
    public async Task VerifyAsync_TopOriginPresent_IsRejected()
    {
        using var assertion = TestAssertion.Create(topOrigin: "https://embedder.maliev.test");
        var verifier = CreateVerifier();

        var result = await verifier.VerifyAsync(assertion.Input, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(PasskeyAssertionFailure.CrossOriginNotAllowed, result.Failure);
    }

    /// <summary>Verifies missing verification or impossible backup-state flags fail closed.</summary>
    [Theory]
    [InlineData(0x01)] // UP only
    [InlineData(0x15)] // UP | UV | BS without BE
    public async Task VerifyAsync_MissingVerificationOrImpossibleBackupState_IsRejected(byte flags)
    {
        using var assertion = TestAssertion.Create(flags: flags);
        var verifier = CreateVerifier();

        var result = await verifier.VerifyAsync(assertion.Input, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(PasskeyAssertionFailure.InvalidAuthenticatorFlags, result.Failure);
    }

    /// <summary>Verifies RP hash and signature tampering are rejected by the FIDO2 verifier.</summary>
    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task VerifyAsync_RpHashOrSignatureTampering_IsRejected(bool wrongRpIdHash, bool tamperSignature)
    {
        using var assertion = TestAssertion.Create(
            authenticatorRpId: wrongRpIdHash ? "attacker.test" : RpId,
            tamperSignature: tamperSignature);
        var verifier = CreateVerifier();

        var result = await verifier.VerifyAsync(assertion.Input, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(PasskeyAssertionFailure.VerificationFailed, result.Failure);
    }

    /// <summary>Verifies stored credential and user-handle ownership cannot be substituted.</summary>
    [Theory]
    [InlineData(true, false, PasskeyAssertionFailure.InvalidCredential)]
    [InlineData(false, true, PasskeyAssertionFailure.InvalidUserHandle)]
    public async Task VerifyAsync_StoredCredentialOwnershipMismatch_IsRejected(
        bool wrongStoredCredential,
        bool wrongStoredUserHandle,
        PasskeyAssertionFailure expectedFailure)
    {
        using var assertion = TestAssertion.Create(
            wrongStoredCredential: wrongStoredCredential,
            wrongStoredUserHandle: wrongStoredUserHandle);
        var verifier = CreateVerifier();

        var result = await verifier.VerifyAsync(assertion.Input, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(expectedFailure, result.Failure);
    }

    /// <summary>Verifies a positive authenticator counter cannot roll backwards.</summary>
    [Fact]
    public async Task VerifyAsync_AuthenticatorCounterRollback_IsRejected()
    {
        using var assertion = TestAssertion.Create(signCount: 5, storedSignCount: 6);
        var verifier = CreateVerifier();

        var result = await verifier.VerifyAsync(assertion.Input, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(PasskeyAssertionFailure.InvalidSignCount, result.Failure);
    }

    private static PasskeyAssertionVerifier CreateVerifier()
    {
        var options = new PasskeyWebAuthnOptions
        {
            RpId = RpId,
            RpName = "MALIEV Test",
            AllowedOrigins = [Origin],
            TimeoutMilliseconds = 300_000,
            ChallengeSize = 32
        };
        var library = new Fido2(new Fido2Configuration
        {
            ServerDomain = options.RpId,
            ServerName = options.RpName,
            Origins = options.AllowedOrigins.ToHashSet(StringComparer.Ordinal),
            Timeout = (uint)options.TimeoutMilliseconds,
            ChallengeSize = options.ChallengeSize
        });
        return new PasskeyAssertionVerifier(
            library,
            Options.Create(options),
            NullLogger<PasskeyAssertionVerifier>.Instance);
    }

    private sealed class TestAssertion : IDisposable
    {
        private readonly ECDsa _key;

        private TestAssertion(ECDsa key, PasskeyAssertionVerificationInput input)
        {
            _key = key;
            Input = input;
        }

        public PasskeyAssertionVerificationInput Input { get; }

        public static TestAssertion Create(
            string origin = Origin,
            bool crossOrigin = false,
            string? topOrigin = null,
            string type = "webauthn.get",
            bool useWrongChallenge = false,
            byte flags = 0x05,
            uint signCount = 1,
            uint storedSignCount = 0,
            bool storedBackupEligible = false,
            bool includeUserHandle = true,
            string authenticatorRpId = RpId,
            bool tamperSignature = false,
            bool wrongStoredCredential = false,
            bool wrongStoredUserHandle = false)
        {
            var challenge = RandomNumberGenerator.GetBytes(32);
            var credentialId = RandomNumberGenerator.GetBytes(32);
            var userHandle = RandomNumberGenerator.GetBytes(16);
            var options = new AssertionOptions
            {
                Challenge = challenge,
                Timeout = 300_000,
                RpId = RpId,
                AllowCredentials = [],
                UserVerification = UserVerificationRequirement.Required,
                Extensions = null
            };
            var clientDataValues = new Dictionary<string, object?>
            {
                ["type"] = type,
                ["challenge"] = ToBase64Url(useWrongChallenge
                    ? RandomNumberGenerator.GetBytes(32)
                    : challenge),
                ["origin"] = origin,
                ["crossOrigin"] = crossOrigin
            };
            if (topOrigin is not null)
            {
                clientDataValues["topOrigin"] = topOrigin;
            }
            var clientData = JsonSerializer.SerializeToUtf8Bytes(clientDataValues);
            var authenticatorData = new byte[37];
            SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(authenticatorRpId)).CopyTo(authenticatorData, 0);
            authenticatorData[32] = flags;
            BinaryPrimitives.WriteUInt32BigEndian(authenticatorData.AsSpan(33, 4), signCount);

            var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var publicKey = new CredentialPublicKey(key, COSE.Algorithm.ES256).GetBytes();
            var signedData = new byte[authenticatorData.Length + SHA256.HashSizeInBytes];
            authenticatorData.CopyTo(signedData, 0);
            SHA256.HashData(clientData).CopyTo(signedData, authenticatorData.Length);
            var signature = key.SignData(
                signedData,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
            if (tamperSignature)
            {
                signature[^1] ^= 0x01;
            }

            var storedCredentialId = wrongStoredCredential
                ? RandomNumberGenerator.GetBytes(32)
                : credentialId;
            var storedUserHandle = wrongStoredUserHandle
                ? RandomNumberGenerator.GetBytes(16)
                : userHandle;

            return new TestAssertion(key, new PasskeyAssertionVerificationInput(
                AssertionOptionsJson: options.ToJson(),
                CredentialId: ToBase64Url(credentialId),
                AuthenticatorData: ToBase64Url(authenticatorData),
                ClientDataJson: ToBase64Url(clientData),
                Signature: ToBase64Url(signature),
                UserHandle: includeUserHandle ? ToBase64Url(userHandle) : null,
                StoredCredentialId: storedCredentialId,
                StoredPublicKeyCose: publicKey,
                StoredUserHandle: storedUserHandle,
                StoredSignCount: storedSignCount,
                StoredBackupEligible: storedBackupEligible));
        }

        public void Dispose() => _key.Dispose();

        private static string ToBase64Url(byte[] value) =>
            Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
