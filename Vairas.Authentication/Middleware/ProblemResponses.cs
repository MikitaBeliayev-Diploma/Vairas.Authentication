using System.Data.Common;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Vairas.Authentication.Business;

namespace Vairas.Authentication.Middleware;


public static class ProblemResponses
{
    public static Task WriteAsync(HttpContext http, int status, string code, string title)
    {
        http.Response.StatusCode = status;
        return http.Response.WriteAsJsonAsync(new ProblemDetails
        {
            Status = status, Title = title, Instance = http.Request.Path,
            Extensions = { ["code"] = code, ["correlationId"] = CorrelationMiddleware.GetId(http) }
        }, options: null, contentType: "application/problem+json", cancellationToken: http.RequestAborted);
    }
}
