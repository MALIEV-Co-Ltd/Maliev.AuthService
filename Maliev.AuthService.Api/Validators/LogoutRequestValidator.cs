using FluentValidation;
using Maliev.AuthService.Api.Models.Request;

namespace Maliev.AuthService.Api.Validators;

public class LogoutRequestValidator : AbstractValidator<LogoutRequest>
{
    public LogoutRequestValidator()
    {
        RuleFor(x => x.RefreshToken)
            .NotEmpty()
            .WithMessage("Refresh token is required");
    }
}
