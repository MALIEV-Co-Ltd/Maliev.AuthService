namespace Maliev.AuthService.Infrastructure.Services;

/// <summary>Defines AuthService's exact contract with IAM workload provisioning.</summary>
public static class ServiceIdentityIamContract
{
    /// <summary>Validates and returns a canonical IAM workload identifier.</summary>
    public static string ValidateWorkloadId(string workloadId)
    {
        if (workloadId is not { Length: > 0 and <= 100 } ||
            workloadId[0] == '-' || workloadId[^1] == '-' ||
            workloadId.Contains("--", StringComparison.Ordinal) ||
            workloadId.Any(character => character is not (
                >= 'a' and <= 'z' or >= '0' and <= '9' or '-')))
        {
            throw new ArgumentException("Workload identifier is not canonical", nameof(workloadId));
        }

        return workloadId;
    }

    /// <summary>Returns the deterministic role identifier IAM must bind for a workload profile.</summary>
    public static string ExpectedRoleId(string workloadId, int profileVersion)
    {
        workloadId = ValidateWorkloadId(workloadId);
        ArgumentOutOfRangeException.ThrowIfLessThan(profileVersion, 1);
        return $"roles.workloads.{workloadId}.v{profileVersion}";
    }
}
