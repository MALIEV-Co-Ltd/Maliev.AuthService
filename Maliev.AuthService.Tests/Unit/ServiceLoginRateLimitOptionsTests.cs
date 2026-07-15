using System.ComponentModel.DataAnnotations;
using Maliev.AuthService.Infrastructure.Security;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public sealed class ServiceLoginRateLimitOptionsTests
{
    [Theory]
    [InlineData(0, 60)]
    [InlineData(1001, 60)]
    [InlineData(100, 0)]
    [InlineData(100, 3601)]
    public void ValuesOutsideBounds_AreInvalid(int permits, int windowSeconds)
    {
        var options = new ServiceLoginRateLimitOptions
        {
            PermitLimit = permits,
            WindowSeconds = windowSeconds
        };

        Assert.False(Validator.TryValidateObject(
            options,
            new ValidationContext(options),
            [],
            validateAllProperties: true));
    }
}
