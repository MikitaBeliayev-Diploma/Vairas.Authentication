using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

public interface IAccountThrottle { void Check(string normalizedEmail, string operation); }
