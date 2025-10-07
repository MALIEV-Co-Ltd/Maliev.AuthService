using FluentValidation;
using Maliev.AuthService.Api.Models.Request;

namespace Maliev.AuthService.Api.Validators;

public class ServiceLoginRequestValidator : AbstractValidator<ServiceLoginRequest>
{
    public ServiceLoginRequestValidator()
    {
        RuleFor(x => x.ClientId)
            .NotEmpty().WithMessage("Client ID is required")
            .Matches(@"^service-.+-.+$")
            .WithMessage("Client ID must follow pattern: service-{environment}-{name}");

        RuleFor(x => x.ClientSecret)
            .NotEmpty().WithMessage("Client secret is required");
    }
}
