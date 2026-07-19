using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using Google.Apis.Auth;
using Maliev.AuthService.Application.Identity;
using Maliev.AuthService.Application.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Maliev.AuthService.Infrastructure.Services;

/// <summary>
/// Validates Google Identity Services ID tokens with Google's supported .NET library.
/// </summary>
public sealed class GoogleIdentityTokenValidator(
    IConfiguration configuration,
    IGoogleIdTokenVerifier googleTokenVerifier,
    ILogger<GoogleIdentityTokenValidator> logger) : IGoogleIdentityTokenValidator
{
    /// <inheritdoc />
    public async Task<GoogleIdentityValidationResult> ValidateAsync(
        string credential,
        string application,
        GoogleIdentityExchangeType exchangeType,
        string expectedNonce,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(credential) ||
            string.IsNullOrWhiteSpace(application) ||
            string.IsNullOrWhiteSpace(expectedNonce))
        {
            return InvalidCredential();
        }

        var applicationSelector = application.Trim().ToLowerInvariant();
        var allowedAudiences = ResolveAllowedAudiences(exchangeType, applicationSelector);
        if (allowedAudiences.Count == 0)
        {
            logger.LogWarning(
                "Google identity exchange rejected an unknown {ExchangeType} application selector {ApplicationSelector}",
                exchangeType,
                applicationSelector);
            return new GoogleIdentityValidationResult
            {
                Success = false,
                ErrorCode = "invalid_audience",
                ErrorDescription = "Google sign-in is not configured for this application"
            };
        }

        GoogleIdentityTokenPayload payload;
        try
        {
            payload = await googleTokenVerifier.VerifyAsync(
                credential,
                allowedAudiences,
                cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException ex)
        {
            logger.LogError(ex, "Google identity credential validation timed out");
            return new GoogleIdentityValidationResult
            {
                Success = false,
                ErrorCode = "service_unavailable",
                ErrorDescription = "Google sign-in validation is temporarily unavailable"
            };
        }
        catch (HttpRequestException ex)
        {
            logger.LogError(ex, "Google identity certificate retrieval failed");
            return new GoogleIdentityValidationResult
            {
                Success = false,
                ErrorCode = "service_unavailable",
                ErrorDescription = "Google sign-in validation is temporarily unavailable"
            };
        }
        catch (Exception ex) when (ex is InvalidJwtException or FormatException or JsonException or Newtonsoft.Json.JsonException)
        {
            logger.LogWarning("Google identity credential validation failed with {FailureType}", ex.GetType().Name);
            return InvalidCredential();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unexpected Google identity credential validation failure");
            return new GoogleIdentityValidationResult
            {
                Success = false,
                ErrorCode = "service_unavailable",
                ErrorDescription = "Google sign-in validation is temporarily unavailable"
            };
        }

        if (string.IsNullOrWhiteSpace(payload.Subject) ||
            string.IsNullOrWhiteSpace(payload.Email))
        {
            return InvalidCredential();
        }

        if (!NonceMatches(expectedNonce, payload.Nonce))
        {
            logger.LogWarning("Google identity credential rejected because its nonce did not match the issued exchange nonce");
            return InvalidCredential();
        }

        var audiences = payload.Audiences
            .Where(audience => !string.IsNullOrWhiteSpace(audience))
            .ToArray();
        if (audiences.Length == 0 ||
            !audiences.Any(audience => allowedAudiences.Contains(audience, StringComparer.Ordinal)))
        {
            return InvalidCredential();
        }

        if (audiences.Length > 1 && string.IsNullOrWhiteSpace(payload.AuthorizedParty))
        {
            return InvalidCredential();
        }

        if (!string.IsNullOrWhiteSpace(payload.AuthorizedParty) &&
            !allowedAudiences.Contains(payload.AuthorizedParty, StringComparer.Ordinal))
        {
            return InvalidCredential();
        }

        if (!payload.EmailVerified)
        {
            return new GoogleIdentityValidationResult
            {
                Success = false,
                ErrorCode = "unverified_email",
                ErrorDescription = "Google email must be verified"
            };
        }

        if (exchangeType == GoogleIdentityExchangeType.Employee)
        {
            var hostedDomain = configuration["GoogleIdentity:Employee:HostedDomain"];
            if (string.IsNullOrWhiteSpace(hostedDomain))
            {
                logger.LogError("Google employee hosted domain is not configured");
                return new GoogleIdentityValidationResult
                {
                    Success = false,
                    ErrorCode = "service_unavailable",
                    ErrorDescription = "Google sign-in is not configured"
                };
            }

            if (!string.Equals(payload.HostedDomain, hostedDomain, StringComparison.OrdinalIgnoreCase) ||
                !payload.Email.EndsWith($"@{hostedDomain}", StringComparison.OrdinalIgnoreCase))
            {
                return new GoogleIdentityValidationResult
                {
                    Success = false,
                    ErrorCode = "invalid_domain",
                    ErrorDescription = $"Only @{hostedDomain} Google Workspace accounts are allowed"
                };
            }
        }

        return new GoogleIdentityValidationResult
        {
            Success = true,
            Identity = new VerifiedGoogleIdentity
            {
                Subject = payload.Subject,
                Email = payload.Email,
                EmailVerified = payload.EmailVerified,
                HostedDomain = payload.HostedDomain,
                FullName = payload.FullName,
                ProfileImageUrl = payload.ProfileImageUrl
            }
        };
    }

    private IReadOnlyCollection<string> ResolveAllowedAudiences(
        GoogleIdentityExchangeType exchangeType,
        string applicationSelector)
    {
        var section = configuration.GetSection(
            $"GoogleIdentity:{exchangeType}:Audiences:{applicationSelector}");
        var audiences = new List<string>();

        if (!string.IsNullOrWhiteSpace(section.Value))
        {
            audiences.Add(section.Value.Trim());
        }

        audiences.AddRange(section
            .GetChildren()
            .Select(child => child.Value)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!.Trim()));

        return audiences.Distinct(StringComparer.Ordinal).ToArray();
    }

    private static GoogleIdentityValidationResult InvalidCredential() => new()
    {
        Success = false,
        ErrorCode = "invalid_google_credential",
        ErrorDescription = "Google credential is invalid or expired"
    };

    private static bool NonceMatches(string expectedNonce, string? tokenNonce)
    {
        if (string.IsNullOrWhiteSpace(tokenNonce))
        {
            return false;
        }

        var expectedHash = SHA256.HashData(Encoding.UTF8.GetBytes(expectedNonce));
        var actualHash = SHA256.HashData(Encoding.UTF8.GetBytes(tokenNonce));
        return CryptographicOperations.FixedTimeEquals(expectedHash, actualHash);
    }
}
