using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.AspNetCore.WebUtilities;
using MimeKit;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration;
using Vairas.Authentication.Configuration.Options;

namespace Vairas.Authentication.Integrations;

public sealed class SmtpChallengeSender(SmtpOptions options) : IChallengeSender
{
    public async Task<DeliveryResult> SendAsync(ChallengeMail mail, CancellationToken ct)
    {
        using var client = new SmtpClient { Timeout = 15000 };
        var sending = false;
        try
        {
            await client.ConnectAsync(options.Host, options.Port, Enum.Parse<SecureSocketOptions>(options.Security), ct);
            if (options.Username is not null) await client.AuthenticateAsync(options.Username, options.Password!, ct);
            var message = CreateMessage(mail);
            sending = true;
            await client.SendAsync(message, ct);
            // QUIT failure after accepted DATA must not turn an accepted message into a retry.
            try { await client.DisconnectAsync(true, ct); } catch (Exception ex) when (ex is IOException or MailKit.ProtocolException or OperationCanceledException) { }
            return new("Sent");
        }
        catch (SmtpCommandException ex)
        {
            var retry = (int)ex.StatusCode is >= 400 and < 500;
            return new(retry ? "Retry" : "Failed", retry ? "SMTP_TEMPORARY_REJECTION" : "SMTP_PERMANENT_REJECTION");
        }
        catch (Exception ex) when (ex is IOException or MailKit.ProtocolException or MailKit.ServiceNotConnectedException or MailKit.ServiceNotAuthenticatedException or
            System.Net.Sockets.SocketException or System.Security.Authentication.AuthenticationException or OperationCanceledException)
        { return new(sending ? "Unknown" : "Retry", sending ? "SMTP_OUTCOME_UNKNOWN" : "SMTP_UNAVAILABLE"); }
    }

    private MimeMessage CreateMessage(ChallengeMail mail)
    {
        var message = new MimeMessage();
        message.From.Add(MailboxAddress.Parse(options.Sender));
        message.To.Add(MailboxAddress.Parse(mail.Recipient));
        message.Subject = mail.Purpose == "VerifyEmail" ? "Verify your Vairas email" : "Reset your Vairas password";
        // Fragment parameters keep the bearer secret out of normal web-server access logs.
        var fragment = QueryHelpers.AddQueryString("", new Dictionary<string, string?> { ["challengeToken"] = mail.Token, ["purpose"] = mail.Purpose });
        message.Body = new TextPart("plain") { Text = "Open this link to continue:\n" + options.ChallengePage + "#" + fragment.TrimStart('?') +
            "\nIf you did not request this, ignore this email. This link is single use." };
        return message;
    }
}
