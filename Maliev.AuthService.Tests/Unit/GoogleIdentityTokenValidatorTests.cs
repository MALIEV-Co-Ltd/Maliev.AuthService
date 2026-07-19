using Google.Apis.Auth;
using Maliev.AuthService.Application.Identity;
using Maliev.AuthService.Infrastructure.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Newtonsoft.Json;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

/// <summary>
/// Verifies AuthService's production boundary around Google's supported ID-token validator.
/// </summary>
public sealed class GoogleIdentityTokenValidatorTests
{
    [Fact]
    public async Task ValidateAsync_MatchingNonceAndAuthorizedParty_AreAccepted()
    {
        var verifier = new RecordingGoogleIdTokenVerifier
        {
            Payload = ValidPayload() with
            {
                Nonce = "one-time-nonce",
                AuthorizedParty = "configured-client-id.apps.googleusercontent.com",
                Audiences = ["configured-client-id.apps.googleusercontent.com"]
            }
        };
        var validator = CreateValidator(verifier, CustomerConfiguration());

        var result = await validator.ValidateAsync(
            "signed-google-credential",
            "web",
            GoogleIdentityExchangeType.Customer,
            "one-time-nonce");

        Assert.True(result.Success);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("different-nonce")]
    public async Task ValidateAsync_MissingOrMismatchedNonce_IsRejected(string? tokenNonce)
    {
        var verifier = new RecordingGoogleIdTokenVerifier
        {
            Payload = ValidPayload() with { Nonce = tokenNonce }
        };
        var validator = CreateValidator(verifier, CustomerConfiguration());

        var result = await validator.ValidateAsync(
            "signed-google-credential",
            "web",
            GoogleIdentityExchangeType.Customer,
            "expected-nonce");

        Assert.False(result.Success);
        Assert.Equal("invalid_google_credential", result.ErrorCode);
    }

    [Fact]
    public async Task ValidateAsync_UnexpectedAuthorizedParty_IsRejected()
    {
        var verifier = new RecordingGoogleIdTokenVerifier
        {
            Payload = ValidPayload() with
            {
                Nonce = "one-time-nonce",
                AuthorizedParty = "attacker-client.apps.googleusercontent.com",
                Audiences = ["configured-client-id.apps.googleusercontent.com"]
            }
        };
        var validator = CreateValidator(verifier, CustomerConfiguration());

        var result = await validator.ValidateAsync(
            "signed-google-credential",
            "web",
            GoogleIdentityExchangeType.Customer,
            "one-time-nonce");

        Assert.False(result.Success);
        Assert.Equal("invalid_google_credential", result.ErrorCode);
    }

    [Fact]
    public async Task ValidateAsync_MultipleAudiencesWithoutAuthorizedParty_IsRejected()
    {
        var verifier = new RecordingGoogleIdTokenVerifier
        {
            Payload = ValidPayload() with
            {
                Nonce = "one-time-nonce",
                AuthorizedParty = null,
                Audiences =
                [
                    "configured-client-id.apps.googleusercontent.com",
                    "another-client.apps.googleusercontent.com"
                ]
            }
        };
        var validator = CreateValidator(verifier, CustomerConfiguration());

        var result = await validator.ValidateAsync(
            "signed-google-credential",
            "web",
            GoogleIdentityExchangeType.Customer,
            "one-time-nonce");

        Assert.False(result.Success);
        Assert.Equal("invalid_google_credential", result.ErrorCode);
    }

    [Fact]
    public async Task ValidateAsync_NewtonsoftMalformedTokenFailure_ReturnsInvalidCredential()
    {
        var verifier = new RecordingGoogleIdTokenVerifier
        {
            Exception = new JsonReaderException("malformed token payload")
        };
        var validator = CreateValidator(verifier, CustomerConfiguration());

        var result = await validator.ValidateAsync(
            "malformed-google-credential",
            "web",
            GoogleIdentityExchangeType.Customer,
            "one-time-nonce");

        Assert.False(result.Success);
        Assert.Equal("invalid_google_credential", result.ErrorCode);
    }

    [Fact]
    public async Task ValidateAsync_UnknownApplication_FailsBeforeTokenValidation()
    {
        var verifier = new RecordingGoogleIdTokenVerifier();
        var validator = CreateValidator(verifier);

        var result = await validator.ValidateAsync(
            "header.payload.signature",
            "unknown-app",
            GoogleIdentityExchangeType.Customer,
            "one-time-nonce");

        Assert.False(result.Success);
        Assert.Equal("invalid_audience", result.ErrorCode);
        Assert.Null(result.Identity);
        Assert.Equal(0, verifier.CallCount);
    }

    [Fact]
    public async Task ValidateAsync_ConfiguredApplication_PassesOnlyConfiguredAudiencesToGoogleVerifier()
    {
        var verifier = new RecordingGoogleIdTokenVerifier
        {
            Payload = ValidPayload() with
            {
                AuthorizedParty = "web-client.apps.googleusercontent.com",
                Audiences = ["web-client.apps.googleusercontent.com"]
            }
        };
        var validator = CreateValidator(verifier, new Dictionary<string, string?>
        {
            ["GoogleIdentity:Customer:Audiences:web:0"] = "web-client.apps.googleusercontent.com",
            ["GoogleIdentity:Customer:Audiences:web:1"] = "shared-client.apps.googleusercontent.com"
        });

        var result = await validator.ValidateAsync(
            "signed-google-credential",
            "WEB",
            GoogleIdentityExchangeType.Customer,
            "one-time-nonce");

        Assert.True(result.Success);
        Assert.NotNull(result.Identity);
        Assert.Equal("verified-google-subject", result.Identity.Subject);
        Assert.Equal("verified.user@example.com", result.Identity.Email);
        Assert.Equal(1, verifier.CallCount);
        Assert.Equal("signed-google-credential", verifier.LastCredential);
        Assert.Equal(
            ["web-client.apps.googleusercontent.com", "shared-client.apps.googleusercontent.com"],
            verifier.LastAudiences);
    }

    [Theory]
    [InlineData("signature")]
    [InlineData("audience")]
    [InlineData("issuer")]
    [InlineData("expired")]
    public async Task ValidateAsync_GoogleTrustCheckFailure_ReturnsCustomerSafeInvalidCredential(string failure)
    {
        var verifier = new RecordingGoogleIdTokenVerifier
        {
            Exception = new InvalidJwtException($"invalid {failure}")
        };
        var validator = CreateValidator(verifier, CustomerConfiguration());

        var result = await validator.ValidateAsync(
            "untrusted-google-credential",
            "web",
            GoogleIdentityExchangeType.Customer,
            "one-time-nonce");

        Assert.False(result.Success);
        Assert.Equal("invalid_google_credential", result.ErrorCode);
        Assert.Equal("Google credential is invalid or expired", result.ErrorDescription);
        Assert.Null(result.Identity);
    }

    [Fact]
    public async Task ValidateAsync_UnverifiedEmail_IsRejected()
    {
        var verifier = new RecordingGoogleIdTokenVerifier
        {
            Payload = ValidPayload() with { EmailVerified = false }
        };
        var validator = CreateValidator(verifier, CustomerConfiguration());

        var result = await validator.ValidateAsync(
            "signed-google-credential",
            "web",
            GoogleIdentityExchangeType.Customer,
            "one-time-nonce");

        Assert.False(result.Success);
        Assert.Equal("unverified_email", result.ErrorCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("other.example")]
    public async Task ValidateAsync_EmployeeHostedDomainMismatch_IsRejected(string? hostedDomain)
    {
        var verifier = new RecordingGoogleIdTokenVerifier
        {
            Payload = ValidPayload() with
            {
                Email = "employee@maliev.com",
                HostedDomain = hostedDomain
            }
        };
        var validator = CreateValidator(verifier, EmployeeConfiguration());

        var result = await validator.ValidateAsync(
            "signed-google-credential",
            "intranet",
            GoogleIdentityExchangeType.Employee,
            "one-time-nonce");

        Assert.False(result.Success);
        Assert.Equal("invalid_domain", result.ErrorCode);
        Assert.Equal("Only @maliev.com Google Workspace accounts are allowed", result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAsync_EmployeeHostedDomainAndVerifiedEmail_AreAccepted()
    {
        var verifier = new RecordingGoogleIdTokenVerifier
        {
            Payload = ValidPayload() with
            {
                Email = "employee@maliev.com",
                HostedDomain = "maliev.com"
            }
        };
        var validator = CreateValidator(verifier, EmployeeConfiguration());

        var result = await validator.ValidateAsync(
            "signed-google-credential",
            "intranet",
            GoogleIdentityExchangeType.Employee,
            "one-time-nonce");

        Assert.True(result.Success);
        Assert.Equal("employee@maliev.com", result.Identity?.Email);
        Assert.Equal("maliev.com", result.Identity?.HostedDomain);
    }

    [Fact]
    public async Task ValidateAsync_GoogleCertificateFailure_ReturnsServiceUnavailable()
    {
        var verifier = new RecordingGoogleIdTokenVerifier
        {
            Exception = new HttpRequestException("certificate endpoint unavailable")
        };
        var validator = CreateValidator(verifier, CustomerConfiguration());

        var result = await validator.ValidateAsync(
            "signed-google-credential",
            "web",
            GoogleIdentityExchangeType.Customer,
            "one-time-nonce");

        Assert.False(result.Success);
        Assert.Equal("service_unavailable", result.ErrorCode);
    }

    [Fact]
    public async Task ValidateAsync_CallerCancellation_Propagates()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var verifier = new RecordingGoogleIdTokenVerifier
        {
            Exception = new OperationCanceledException(cancellation.Token)
        };
        var validator = CreateValidator(verifier, CustomerConfiguration());

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => validator.ValidateAsync(
            "signed-google-credential",
            "web",
            GoogleIdentityExchangeType.Customer,
            "one-time-nonce",
            cancellation.Token));
    }

    [Fact]
    public async Task ValidateAsync_EmptyCredential_FailsWithoutCallingGoogle()
    {
        var verifier = new RecordingGoogleIdTokenVerifier();
        var validator = CreateValidator(verifier, EmployeeConfiguration());

        var result = await validator.ValidateAsync(
            " ",
            "intranet",
            GoogleIdentityExchangeType.Employee,
            "one-time-nonce");

        Assert.False(result.Success);
        Assert.Equal("invalid_google_credential", result.ErrorCode);
        Assert.Equal(0, verifier.CallCount);
    }

    private static Dictionary<string, string?> CustomerConfiguration() => new()
    {
        ["GoogleIdentity:Customer:Audiences:web:0"] = "configured-client-id.apps.googleusercontent.com"
    };

    private static Dictionary<string, string?> EmployeeConfiguration() => new()
    {
        ["GoogleIdentity:Employee:HostedDomain"] = "maliev.com",
        ["GoogleIdentity:Employee:Audiences:intranet:0"] = "configured-client-id.apps.googleusercontent.com"
    };

    private static GoogleIdentityTokenPayload ValidPayload() => new()
    {
        Subject = "verified-google-subject",
        Email = "verified.user@example.com",
        EmailVerified = true,
        Nonce = "one-time-nonce",
        AuthorizedParty = "configured-client-id.apps.googleusercontent.com",
        Audiences = ["configured-client-id.apps.googleusercontent.com"],
        FullName = "Verified User",
        ProfileImageUrl = "https://lh3.googleusercontent.com/a/verified-user"
    };

    private static GoogleIdentityTokenValidator CreateValidator(
        IGoogleIdTokenVerifier verifier,
        IReadOnlyDictionary<string, string?>? values = null)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(values ?? new Dictionary<string, string?>())
            .Build();
        return new GoogleIdentityTokenValidator(
            configuration,
            verifier,
            NullLogger<GoogleIdentityTokenValidator>.Instance);
    }

    private sealed class RecordingGoogleIdTokenVerifier : IGoogleIdTokenVerifier
    {
        public GoogleIdentityTokenPayload Payload { get; init; } = ValidPayload();

        public Exception? Exception { get; init; }

        public int CallCount { get; private set; }

        public string? LastCredential { get; private set; }

        public IReadOnlyCollection<string> LastAudiences { get; private set; } = [];

        public Task<GoogleIdentityTokenPayload> VerifyAsync(
            string credential,
            IReadOnlyCollection<string> allowedAudiences,
            CancellationToken cancellationToken)
        {
            CallCount++;
            LastCredential = credential;
            LastAudiences = allowedAudiences.ToArray();
            if (Exception is not null)
            {
                return Task.FromException<GoogleIdentityTokenPayload>(Exception);
            }

            return Task.FromResult(Payload);
        }
    }
}
