namespace Vairas.Authentication.Configuration.Options;


public sealed class SmtpOptions
{
    public string Host { get; set; } = "localhost";
    public int Port { get; set; } = 587;
    public string Security { get; set; } = "StartTls";
    public string? Username { get; set; }
    public string? Password { get; set; }
    public string Sender { get; set; } = "";
    public string ChallengePage { get; set; } = "";
    public bool WorkerEnabled { get; set; } = true;
}
