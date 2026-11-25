using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

public sealed record ExternalSubject(string Issuer, string Subject);
