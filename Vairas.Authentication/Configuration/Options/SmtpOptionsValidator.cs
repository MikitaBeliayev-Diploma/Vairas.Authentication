using System.Net.Mail;
using MailKit.Security;
using Microsoft.Extensions.Options;

namespace Vairas.Authentication.Configuration.Options;

public sealed class SmtpOptionsValidator(IHostEnvironment environment) : IValidateOptions<SmtpOptions>
{
    public ValidateOptionsResult Validate(string? name, SmtpOptions smtp)
    {
        if (!Enum.TryParse<SecureSocketOptions>(smtp.Security, out var security) ||
            security is not (SecureSocketOptions.StartTls or SecureSocketOptions.SslOnConnect or SecureSocketOptions.None) ||
            smtp.Port is < 1 or > 65535 || string.IsNullOrWhiteSpace(smtp.Host) || !MailboxAddressValid(smtp.Sender) || !HttpsUrl.IsValid(smtp.ChallengePage))
            return ValidateOptionsResult.Fail("Configure SMTP, its sender and the HTTPS frontend challenge page.");
        if (security == SecureSocketOptions.None && (!(environment.IsDevelopment() || environment.IsEnvironment("Testing")) ||
            smtp.Host is not ("localhost" or "127.0.0.1" or "::1")))
            return ValidateOptionsResult.Fail("Unencrypted SMTP is limited to explicit local development.");
        if ((smtp.Username is null) != (smtp.Password is null))
            return ValidateOptionsResult.Fail("Supply both SMTP username and password, or neither.");
        return ValidateOptionsResult.Success;
    }

    private static bool MailboxAddressValid(string value) => MailAddress.TryCreate(value, out var parsed) && parsed.Address == value;
}
