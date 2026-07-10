using Google.Apis.Auth;
using System.IdentityModel.Tokens.Jwt;

namespace Maliev.AuthService.Infrastructure.Services;

/// <summary>
/// Verifies a Google-issued ID token against an explicit audience allowlist.
/// </summary>
public interface IGoogleIdTokenVerifier
{
    /// <summary>
    /// Verifies the credential with Google's supported signature and claims validator.
    /// </summary>
    /// <param name="credential">The raw Google Identity Services credential.</param>
    /// <param name="allowedAudiences">The exact OAuth client IDs accepted for this application.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The verified Google identity token payload.</returns>
    Task<GoogleIdentityTokenPayload> VerifyAsync(
        string credential,
        IReadOnlyCollection<string> allowedAudiences,
        CancellationToken cancellationToken);
}

/// <summary>
/// Verified Google ID-token claims used by AuthService.
/// </summary>
public sealed record GoogleIdentityTokenPayload
{
    /// <summary>Gets the stable Google OpenID Connect subject.</summary>
    public required string Subject { get; init; }

    /// <summary>Gets the email asserted by the verified Google token.</summary>
    public required string Email { get; init; }

    /// <summary>Gets a value indicating whether Google verified the email.</summary>
    public bool EmailVerified { get; init; }

    /// <summary>Gets the optional Google Workspace hosted-domain claim.</summary>
    public string? HostedDomain { get; init; }

    /// <summary>Gets the nonce bound to the browser credential request.</summary>
    public string? Nonce { get; init; }

    /// <summary>Gets the OAuth client identified by the optional azp claim.</summary>
    public string? AuthorizedParty { get; init; }

    /// <summary>Gets every audience asserted by the verified token.</summary>
    public IReadOnlyCollection<string> Audiences { get; init; } = [];

    /// <summary>Gets the optional display name.</summary>
    public string? FullName { get; init; }

    /// <summary>Gets the optional profile image URL.</summary>
    public string? ProfileImageUrl { get; init; }
}

/// <summary>
/// Production adapter for Google's supported .NET ID-token validator.
/// </summary>
public sealed class GoogleJsonWebSignatureVerifier : IGoogleIdTokenVerifier
{
    /// <inheritdoc />
    public async Task<GoogleIdentityTokenPayload> VerifyAsync(
        string credential,
        IReadOnlyCollection<string> allowedAudiences,
        CancellationToken cancellationToken)
    {
        var settings = new GoogleJsonWebSignature.ValidationSettings
        {
            Audience = allowedAudiences
        };
        var payload = await GoogleJsonWebSignature
            .ValidateAsync(credential, settings)
            .WaitAsync(cancellationToken);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(credential);
        var authorizedParty = jwt.Payload.TryGetValue("azp", out var azp)
            ? Convert.ToString(azp, System.Globalization.CultureInfo.InvariantCulture)
            : null;

        return new GoogleIdentityTokenPayload
        {
            Subject = payload.Subject,
            Email = payload.Email,
            EmailVerified = payload.EmailVerified,
            HostedDomain = payload.HostedDomain,
            Nonce = payload.Nonce,
            AuthorizedParty = authorizedParty,
            Audiences = payload.AudienceAsList?.ToArray() ?? [],
            FullName = payload.Name,
            ProfileImageUrl = payload.Picture
        };
    }
}
