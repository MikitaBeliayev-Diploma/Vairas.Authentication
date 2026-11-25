using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

/// <summary>Local credentials for registration or login.</summary>
public sealed record CredentialsRequest(string Email, string Password);
