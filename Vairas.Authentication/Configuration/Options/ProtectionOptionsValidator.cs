using Microsoft.Extensions.Options;

namespace Vairas.Authentication.Configuration.Options;

public sealed class ProtectionOptionsValidator : IValidateOptions<ProtectionOptions>
{
    public ValidateOptionsResult Validate(string? name, ProtectionOptions options) =>
        string.IsNullOrWhiteSpace(options.KeyRingPath) || !Path.IsPathFullyQualified(options.KeyRingPath)
            ? ValidateOptionsResult.Fail("Configure an absolute protected key-ring directory outside source control.")
            : ValidateOptionsResult.Success;
}
