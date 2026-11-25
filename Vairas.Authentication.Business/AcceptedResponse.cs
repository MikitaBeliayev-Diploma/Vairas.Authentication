using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

/// <summary>A deliberately non-disclosing acknowledgment.</summary>
public sealed record AcceptedResponse(string Message = "Request accepted.");
