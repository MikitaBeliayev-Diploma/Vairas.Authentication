using System.Text.RegularExpressions;
using Vairas.Authentication.Business;

namespace Vairas.Authentication.Middleware;

public sealed partial class CorrelationMiddleware(RequestDelegate next, ILogger<CorrelationMiddleware> logger)
{
    private const string Key = "Vairas.CorrelationId";
    private const string AuditKey = "Vairas.SecurityCorrelationId";
    [GeneratedRegex("^[A-Za-z0-9._:/-]{1,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeId();
    public static string GetId(HttpContext http) => http.Items[Key]?.ToString() ?? http.TraceIdentifier;
    public static AuditContext Audit(HttpContext http) => new((Guid)http.Items[AuditKey]!);
    public async Task InvokeAsync(HttpContext http)
    {
        var supplied = http.Request.Headers["X-Correlation-ID"].ToString();
        var id = SafeId().IsMatch(supplied) ? supplied : Guid.NewGuid().ToString("D");
        var audit = Guid.TryParse(id, out var parsed) && parsed != Guid.Empty ? parsed : Guid.NewGuid();
        http.Items[Key] = id; http.Items[AuditKey] = audit;
        http.Response.Headers["X-Correlation-ID"] = id;
        using var scope = logger.BeginScope(new Dictionary<string, object> { ["CorrelationId"] = id, ["SecurityCorrelationId"] = audit });
        if (http.Request.Path.StartsWithSegments("/api/v1/auth") || http.Request.Path == "/connect/token")
        {
            http.Response.Headers.CacheControl = "no-store";
            http.Response.Headers.Pragma = "no-cache";
        }
        await next(http);
        logger.LogInformation("{Method} {Path} completed with {StatusCode}", http.Request.Method, http.Request.Path.Value, http.Response.StatusCode);
    }
}
