using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

/// <summary>Request a verification or password-reset email.</summary>
public sealed record ChallengeRequest(string Email, string Purpose);
