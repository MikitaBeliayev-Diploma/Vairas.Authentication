using System.Security.Cryptography;
using System.Text;

namespace Vairas.Authentication.Business;

/// <summary>Only Authentication's verified login address is eligible; this is not a profile-email assertion.</summary>
public sealed record VerifiedEmailResponse(Guid IdentityId, bool Eligible, string? Email, string Revision, DateTimeOffset ValidUntil);
