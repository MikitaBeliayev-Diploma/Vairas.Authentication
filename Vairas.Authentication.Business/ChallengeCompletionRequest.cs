using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

/// <summary>Consume an emailed challenge; ResetPassword requires NewPassword.</summary>
public sealed record ChallengeCompletionRequest(string ChallengeToken, string? NewPassword);
