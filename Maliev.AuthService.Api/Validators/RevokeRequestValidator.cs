using FluentValidation;
using Maliev.AuthService.Api.Models.Request;

namespace Maliev.AuthService.Api.Validators;

public class RevokeRequestValidator : AbstractValidator<RevokeRequest>
{
    public RevokeRequestValidator()
    {
        RuleFor(x => x.Token)
            .NotEmpty().WithMessage("Token is required");
    }
}
