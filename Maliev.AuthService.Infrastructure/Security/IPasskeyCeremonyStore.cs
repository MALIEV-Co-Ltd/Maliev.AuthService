using Maliev.AuthService.Domain.Entities;

namespace Maliev.AuthService.Infrastructure.Security;

/// <summary>
/// Issues and atomically consumes caller-bound WebAuthn assertion ceremonies.
/// </summary>
public interface IPasskeyCeremonyStore
{
    /// <summary>Persists a new assertion ceremony.</summary>
    /// <param name="serviceName">The authenticated service caller.</param>
    /// <param name="application">The normalized application audience.</param>
    /// <param name="expectedUserType">The principal audience permitted to complete the ceremony.</param>
    /// <param name="assertionOptionsJson">The original FIDO2 assertion options.</param>
    /// <param name="challenge">The server-generated challenge.</param>
    /// <param name="cancellationToken">Token used to cancel persistence.</param>
    /// <returns>The browser-visible flow ID and expiration.</returns>
    Task<PasskeyCeremonyIssue> IssueAsync(
        string serviceName,
        string application,
        UserType expectedUserType,
        string assertionOptionsJson,
        byte[] challenge,
        CancellationToken cancellationToken);

    /// <summary>Atomically consumes a matching, unexpired assertion ceremony.</summary>
    /// <param name="flowId">The opaque flow identifier returned at issue time.</param>
    /// <param name="serviceName">The authenticated service caller.</param>
    /// <param name="application">The normalized application audience.</param>
    /// <param name="cancellationToken">Token used to cancel persistence.</param>
    /// <returns>The server-owned ceremony state, or <see langword="null"/>.</returns>
    Task<PasskeyCeremonyState?> ConsumeAsync(
        string flowId,
        string serviceName,
        string application,
        CancellationToken cancellationToken);
}

/// <summary>
/// Contains the browser-visible result of issuing an assertion ceremony.
/// </summary>
/// <param name="FlowId">The random, opaque flow identifier.</param>
/// <param name="ExpiresAtUtc">The UTC expiration timestamp.</param>
public sealed record PasskeyCeremonyIssue(string FlowId, DateTime ExpiresAtUtc);

/// <summary>
/// Contains the server-owned state recovered by a successful one-time consume.
/// </summary>
/// <param name="AssertionOptionsJson">The original FIDO2 assertion options.</param>
/// <param name="ExpectedUserType">The principal audience bound at ceremony issue time.</param>
public sealed record PasskeyCeremonyState(
    string AssertionOptionsJson,
    UserType ExpectedUserType);
