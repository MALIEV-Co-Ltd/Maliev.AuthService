using System.ComponentModel.DataAnnotations;
using Maliev.AuthService.Infrastructure.Security;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public sealed class ServiceTokenOptionsTests
{
    [Theory]
    [InlineData(59)]
    [InlineData(3601)]
    public void ServiceTokenExpirationOutsideBound_IsInvalid(int seconds)
    {
        var options = new ServiceTokenOptions
        {
            ServiceTokenExpirationInSeconds = seconds
        };

        Assert.False(Validator.TryValidateObject(
            options,
            new ValidationContext(options),
            [],
            validateAllProperties: true));
    }
}
