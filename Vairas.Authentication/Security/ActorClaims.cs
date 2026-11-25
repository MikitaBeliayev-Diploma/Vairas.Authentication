using System.Security.Claims;
using Vairas.Authentication.Business;

namespace Vairas.Authentication.Security;

public static class ActorClaims
{
    /// <summary>The authenticated user and session from validated token claims.</summary>
    public static UserActor Actor(ClaimsPrincipal principal) => new(Guid.Parse(principal.FindFirstValue("sub")!), Guid.Parse(principal.FindFirstValue("sid")!));
}
