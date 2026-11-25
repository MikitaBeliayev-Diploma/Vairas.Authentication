using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

public sealed record ChallengeMail(string Recipient, string Purpose, string Token);
