using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Vairas.Authentication.Business;

namespace Vairas.Authentication.Middleware;


public sealed class ApiExceptionHandler(ILogger<ApiExceptionHandler> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext http, Exception exception, CancellationToken ct)
    {
        // A client that went away is not a server failure; there is nobody to answer.
        if (exception is OperationCanceledException && http.RequestAborted.IsCancellationRequested) return true;
        var (status, code, message) = exception switch
        {
            BusinessException e => (StatusOf(e), e.Code, e.Message),
            BadHttpRequestException => (400, "VALIDATION_FAILED", "The request is invalid."),
            _ => (500, "INTERNAL_ERROR", "The request could not be completed.")
        };
        // Exceptions from providers can include secret-bearing values. Record only their type and safe code.
        logger.Log(status >= 500 ? LogLevel.Error : LogLevel.Information, "Authentication request failed: {ErrorType}, {ErrorCode}", exception.GetType().Name, code);
        if (http.Items["Vairas.TokenExchange"] is true && status < 500)
        {
            http.Response.StatusCode = status; http.Response.Headers.CacheControl = "no-store"; http.Response.Headers.Pragma = "no-cache";
            var error = status == 401 ? "invalid_client" : code switch { "INVALID_SCOPE" => "invalid_scope", "INVALID_TARGET" => "invalid_target", "UNSUPPORTED_GRANT_TYPE" => "unsupported_grant_type", "VALIDATION_FAILED" => "invalid_request", _ => "invalid_grant" };
            await http.Response.WriteAsJsonAsync(new { error, error_description = "The requested token exchange is not permitted.", code, correlationId = CorrelationMiddleware.GetId(http) }, ct);
            return true;
        }
        if (status == 401) http.Response.Headers.WWWAuthenticate = "Bearer";
        if (status == 429) http.Response.Headers.RetryAfter = "60";
        await ProblemResponses.WriteAsync(http, status, code, message);
        return true;
    }

    private static int StatusOf(BusinessException exception) => exception switch
    {
        BadRequestException => StatusCodes.Status400BadRequest,
        UnauthorizedException => StatusCodes.Status401Unauthorized,
        ForbiddenException => StatusCodes.Status403Forbidden,
        NotFoundException => StatusCodes.Status404NotFound,
        ConflictException => StatusCodes.Status409Conflict,
        UnprocessableEntityException => StatusCodes.Status422UnprocessableEntity,
        TooManyRequestsException => StatusCodes.Status429TooManyRequests,
        ServiceUnavailableException => StatusCodes.Status503ServiceUnavailable,
        _ => StatusCodes.Status500InternalServerError
    };
}
