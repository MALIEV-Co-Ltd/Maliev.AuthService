namespace Maliev.AuthService.Infrastructure.Security;

/// <summary>
/// Verifies a WebAuthn assertion against server-owned ceremony and credential state.
/// </summary>
public interface IPasskeyAssertionVerifier
{
    /// <summary>Verifies an assertion and returns the updated authenticator state.</summary>
    /// <param name="input">The assertion and server-owned verification state.</param>
    /// <param name="cancellationToken">Token used to cancel verification.</param>
    /// <returns>The fail-closed verification result.</returns>
    Task<PasskeyAssertionVerificationResult> VerifyAsync(
        PasskeyAssertionVerificationInput input,
        CancellationToken cancellationToken);
}

/// <summary>
/// Contains the browser assertion plus server-owned options and credential state.
/// </summary>
/// <param name="AssertionOptionsJson">The original FIDO2 assertion options issued by the server.</param>
/// <param name="CredentialId">The canonical Base64URL credential identifier returned by the browser.</param>
/// <param name="AuthenticatorData">The Base64URL authenticator data.</param>
/// <param name="ClientDataJson">The Base64URL raw client data JSON.</param>
/// <param name="Signature">The Base64URL authenticator signature.</param>
/// <param name="UserHandle">The Base64URL discoverable-credential user handle.</param>
/// <param name="StoredCredentialId">The credential identifier stored after verified registration.</param>
/// <param name="StoredPublicKeyCose">The COSE public key stored after verified registration.</param>
/// <param name="StoredUserHandle">The user handle stored after verified registration.</param>
/// <param name="StoredSignCount">The last committed authenticator signature counter.</param>
/// <param name="StoredBackupEligible">The immutable backup-eligibility state from registration.</param>
public sealed record PasskeyAssertionVerificationInput(
    string AssertionOptionsJson,
    string CredentialId,
    string AuthenticatorData,
    string ClientDataJson,
    string Signature,
    string? UserHandle,
    byte[] StoredCredentialId,
    byte[] StoredPublicKeyCose,
    byte[] StoredUserHandle,
    uint StoredSignCount,
    bool StoredBackupEligible);

/// <summary>
/// Represents the outcome of passkey assertion verification.
/// </summary>
/// <param name="Success">Whether every MALIEV and WebAuthn check succeeded.</param>
/// <param name="SignCount">The verified authenticator signature counter.</param>
/// <param name="IsBackedUp">The current authenticator backup state.</param>
/// <param name="Failure">The internal fail-closed category.</param>
public sealed record PasskeyAssertionVerificationResult(
    bool Success,
    uint SignCount,
    bool IsBackedUp,
    PasskeyAssertionFailure Failure)
{
    /// <summary>Creates a failed verification result without authenticated state.</summary>
    /// <param name="failure">The internal failure category.</param>
    /// <returns>A failed result.</returns>
    public static PasskeyAssertionVerificationResult Failed(PasskeyAssertionFailure failure) =>
        new(false, 0, false, failure);
}

/// <summary>
/// Internal fail-closed categories used by tests and security telemetry.
/// </summary>
public enum PasskeyAssertionFailure
{
    /// <summary>No failure occurred.</summary>
    None = 0,

    /// <summary>A Base64URL field was malformed, non-canonical, or outside its bound.</summary>
    InvalidEncoding,

    /// <summary>The stored assertion options were invalid or did not match current policy.</summary>
    InvalidOptions,

    /// <summary>The signed browser client data was malformed or inconsistent.</summary>
    InvalidClientData,

    /// <summary>The signed browser origin was not an exact allowed origin.</summary>
    InvalidOrigin,

    /// <summary>The browser reported a cross-origin ceremony.</summary>
    CrossOriginNotAllowed,

    /// <summary>The authenticator flags were missing, reserved, or unsolicited.</summary>
    InvalidAuthenticatorFlags,

    /// <summary>The credential's immutable backup eligibility changed.</summary>
    BackupEligibilityChanged,

    /// <summary>The authenticator signature counter regressed or reset unexpectedly.</summary>
    InvalidSignCount,

    /// <summary>The discoverable credential user handle was missing or did not match.</summary>
    InvalidUserHandle,

    /// <summary>The browser credential identifier did not match stored credential state.</summary>
    InvalidCredential,

    /// <summary>The standards-compliant FIDO2 verifier rejected the assertion.</summary>
    VerificationFailed
}
