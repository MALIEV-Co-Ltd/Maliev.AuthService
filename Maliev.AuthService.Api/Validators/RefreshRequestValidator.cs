using FluentValidation;
using Maliev.AuthService.Api.Models.Request;

namespace Maliev.AuthService.Api.Validators;

public class RefreshRequestValidator : AbstractValidator<RefreshRequest>
{
    public RefreshRequestValidator()
    {
        RuleFor(x => x.RefreshToken)
            .NotEmpty().WithMessage("Refresh token is required");
    }
}
