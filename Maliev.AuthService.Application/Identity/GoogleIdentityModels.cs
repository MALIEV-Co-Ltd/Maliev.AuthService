namespace Maliev.AuthService.Application.Identity;

/// <summary>
/// Identifies the AuthService exchange boundary that is validating a Google credential.
/// </summary>
public enum GoogleIdentityExchangeType
{
    /// <summary>
    /// Employee Google Workspace exchange.
    /// </summary>
    Employee,

    /// <summary>
    /// Customer Google account exchange.
    /// </summary>
    Customer
}

/// <summary>
/// Identity claims established by validating a Google-issued ID token.
/// </summary>
public sealed class VerifiedGoogleIdentity
{
    /// <summary>
    /// Gets the stable Google OpenID Connect subject identifier.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// Gets the verified email address from the Google token.
    /// </summary>
    public required string Email { get; init; }

    /// <summary>
    /// Gets a value indicating whether Google verified the email address.
    /// </summary>
    public bool EmailVerified { get; init; }

    /// <summary>
    /// Gets the optional Google Workspace hosted-domain claim.
    /// </summary>
    public string? HostedDomain { get; init; }

    /// <summary>
    /// Gets the optional display name from the Google token.
    /// </summary>
    public string? FullName { get; init; }

    /// <summary>
    /// Gets the optional profile image URL from the Google token.
    /// </summary>
    public string? ProfileImageUrl { get; init; }
}

/// <summary>
/// Result of validating a Google Identity Services credential.
/// </summary>
public sealed class GoogleIdentityValidationResult
{
    /// <summary>
    /// Gets a value indicating whether the credential was accepted.
    /// </summary>
    public bool Success { get; init; }

    /// <summary>
    /// Gets the verified identity when validation succeeds.
    /// </summary>
    public VerifiedGoogleIdentity? Identity { get; init; }

    /// <summary>
    /// Gets the stable error code when validation fails.
    /// </summary>
    public string? ErrorCode { get; init; }

    /// <summary>
    /// Gets the safe, user-facing error description when validation fails.
    /// </summary>
    public string? ErrorDescription { get; init; }
}

/// <summary>
/// One-time nonce issued for an official Google Identity Services credential request.
/// </summary>
/// <param name="Id">The server-side nonce record identifier.</param>
/// <param name="Nonce">The raw nonce supplied to Google Identity Services.</param>
/// <param name="ExpiresAtUtc">The UTC expiration timestamp.</param>
public sealed record GoogleIdentityNonceIssue(Guid Id, string Nonce, DateTime ExpiresAtUtc);
