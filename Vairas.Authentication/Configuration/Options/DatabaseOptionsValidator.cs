using Microsoft.Extensions.Options;

namespace Vairas.Authentication.Configuration.Options;

public sealed class DatabaseOptionsValidator : IValidateOptions<DatabaseOptions>
{
    public ValidateOptionsResult Validate(string? name, DatabaseOptions options) =>
        string.IsNullOrWhiteSpace(options.Authentication)
            ? ValidateOptionsResult.Fail("ConnectionStrings:Authentication is required.")
            : ValidateOptionsResult.Success;
}
