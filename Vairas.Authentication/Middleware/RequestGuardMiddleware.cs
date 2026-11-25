using System.Net;
using Vairas.Authentication.Configuration.Options;

namespace Vairas.Authentication.Middleware;

/// <summary>Rejects plain-HTTP requests from non-loopback callers and cross-origin auth POSTs from unlisted browser origins.</summary>
public sealed class RequestGuardMiddleware(RequestDelegate next, AuthOptions auth)
{
    public async Task InvokeAsync(HttpContext http)
    {
        if (!http.Request.IsHttps && (http.Connection.RemoteIpAddress is null || !IPAddress.IsLoopback(http.Connection.RemoteIpAddress)))
        {
            await ProblemResponses.WriteAsync(http, 403, "TLS_REQUIRED", "HTTPS is required.");
            return;
        }
        if (http.Request.Method == "POST" && http.Request.Path.StartsWithSegments("/api/v1/auth") && http.Request.Headers.TryGetValue("Origin", out var origin) &&
            !auth.BrowserOrigins.Contains(origin.ToString(), StringComparer.Ordinal))
        {
            await ProblemResponses.WriteAsync(http, 403, "ORIGIN_NOT_ALLOWED", "The browser origin is not permitted.");
            return;
        }
        await next(http);
    }
}
