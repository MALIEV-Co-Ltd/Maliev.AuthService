using FluentValidation;
using Maliev.AuthService.Api.Models.Request;

namespace Maliev.AuthService.Api.Validators;

public class LoginRequestValidator : AbstractValidator<LoginRequest>
{
    public LoginRequestValidator()
    {
        RuleFor(x => x.Username)
            .NotEmpty().WithMessage("Username is required")
            .MaximumLength(255).WithMessage("Username must not exceed 255 characters");

        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Password is required");

        RuleFor(x => x.UserType)
            .NotEmpty().WithMessage("User type is required")
            .Must(x => x == "customer" || x == "employee")
            .WithMessage("User type must be 'customer' or 'employee'");
    }
}
