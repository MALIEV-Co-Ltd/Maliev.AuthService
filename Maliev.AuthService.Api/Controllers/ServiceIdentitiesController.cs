using Asp.Versioning;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Maliev.AuthService.Api.Authorization;
using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Infrastructure.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;

namespace Maliev.AuthService.Api.Controllers;

/// <summary>Manages least-privilege workload identities and versioned service credentials.</summary>
[ApiController]
[ApiVersion("1")]
[Route("auth/v{version:apiVersion}/service-identities")]
public sealed class ServiceIdentitiesController(IServiceIdentityManager manager) : ControllerBase
{
    /// <summary>Provisions or resumes an IAM-backed service identity operation.</summary>
    [HttpPut("{workloadId}")]
    [RequirePermission(
        AuthPermissions.ProvisionServiceIdentities,
        IsCritical = true,
        RequireLiveCheck = true,
        AuditPurpose = "Provision service identity")]
    public async Task<IActionResult> Provision(
        string workloadId,
        [FromBody] ProvisionServiceIdentityRequest request,
        CancellationToken cancellationToken)
    {
        if (!TryGetEmployeeActor(out var actorId) || !TryGetBearerToken(out var bearerToken))
        {
            return Forbid();
        }

        try
        {
            var result = await manager.ProvisionAsync(
                workloadId,
                request,
                actorId,
                bearerToken,
                cancellationToken);
            MarkSecretResponseNonCacheable();
            return Ok(result);
        }
        catch (ServiceIdentityConflictException exception)
        {
            return Conflict(new { error = exception.Message });
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { error = exception.Message });
        }
        catch (HttpRequestException exception) when (exception.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            return Forbid();
        }
        catch (HttpRequestException exception) when (exception.StatusCode == System.Net.HttpStatusCode.Conflict)
        {
            return Conflict(new
            {
                error = "iam_conflict",
                error_description = "IAM rejected the workload identity operation as conflicting"
            });
        }
        catch (HttpRequestException)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new
            {
                error = "iam_unavailable",
                error_description = "IAM could not authoritatively provision the workload identity"
            });
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new
            {
                error = "iam_unavailable",
                error_description = "IAM could not authoritatively provision the workload identity"
            });
        }
    }

    /// <summary>Gets metadata for a managed service identity without secret material.</summary>
    [HttpGet("{workloadId}")]
    [RequirePermission(
        AuthPermissions.ReadServiceIdentities,
        IsCritical = true,
        RequireLiveCheck = true,
        AuditPurpose = "Read service identity")]
    public async Task<IActionResult> Get(string workloadId, CancellationToken cancellationToken)
    {
        if (!TryGetEmployeeActor(out _))
        {
            return Forbid();
        }

        try
        {
            var result = await manager.GetAsync(workloadId, cancellationToken);
            return result is null ? NotFound() : Ok(result);
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { error = exception.Message });
        }
    }

    /// <summary>Rotates a service credential and applies bounded prior-version grace.</summary>
    [HttpPost("{workloadId}/rotations")]
    [RequirePermission(
        AuthPermissions.RotateServiceIdentities,
        IsCritical = true,
        RequireLiveCheck = true,
        AuditPurpose = "Rotate service identity")]
    public async Task<IActionResult> Rotate(
        string workloadId,
        [FromBody] RotateServiceIdentityRequest request,
        CancellationToken cancellationToken)
    {
        if (!TryGetEmployeeActor(out var actorId))
        {
            return Forbid();
        }

        try
        {
            var result = await manager.RotateAsync(workloadId, request, actorId, cancellationToken);
            MarkSecretResponseNonCacheable();
            return Ok(result);
        }
        catch (ServiceIdentityNotFoundException)
        {
            return NotFound();
        }
        catch (ServiceIdentityConflictException exception)
        {
            return Conflict(new { error = exception.Message });
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { error = exception.Message });
        }
    }

    /// <summary>Logically revokes a service identity and all of its secret versions.</summary>
    [HttpPost("{workloadId}/revocations")]
    [RequirePermission(
        AuthPermissions.RevokeServiceIdentities,
        IsCritical = true,
        RequireLiveCheck = true,
        AuditPurpose = "Revoke service identity")]
    public async Task<IActionResult> Revoke(
        string workloadId,
        [FromBody] RevokeServiceIdentityRequest request,
        CancellationToken cancellationToken)
    {
        if (!TryGetEmployeeActor(out var actorId))
        {
            return Forbid();
        }

        try
        {
            await manager.RevokeAsync(workloadId, request, actorId, cancellationToken);
            return NoContent();
        }
        catch (ServiceIdentityNotFoundException)
        {
            return NotFound();
        }
        catch (ServiceIdentityConflictException exception)
        {
            return Conflict(new { error = exception.Message });
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { error = exception.Message });
        }
    }

    private bool TryGetEmployeeActor(out Guid actorId)
    {
        actorId = Guid.Empty;
        var userTypes = User.FindAll("user_type").Select(claim => claim.Value).ToList();
        if (userTypes.Count != 1 || userTypes[0] != "employee")
        {
            return false;
        }

        var subjects = User.FindAll("sub").Select(claim => claim.Value).ToList();
        return subjects.Count == 1 &&
            Guid.TryParseExact(subjects[0], "D", out actorId) &&
            actorId != Guid.Empty &&
            subjects[0] == actorId.ToString("D");
    }

    private bool TryGetBearerToken(out string token)
    {
        token = string.Empty;
        if (!Request.Headers.TryGetValue(HeaderNames.Authorization, out var values) || values.Count != 1)
        {
            return false;
        }

        const string prefix = "Bearer ";
        var value = values[0];
        if (value is null || !value.StartsWith(prefix, StringComparison.Ordinal) || value.Length <= prefix.Length)
        {
            return false;
        }

        token = value[prefix.Length..];
        return token.Length <= 16_384 && token == token.Trim();
    }

    private void MarkSecretResponseNonCacheable()
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
    }
}
