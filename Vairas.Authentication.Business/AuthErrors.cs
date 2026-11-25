using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

/// <summary>Factories for the common application errors; each returns the category exception for the intended HTTP semantics.</summary>
public static class AuthErrors
{
    public static BadRequestException Invalid() => new("VALIDATION_FAILED", "The request is invalid.");
    public static UnauthorizedException Denied() => new("AUTHENTICATION_FAILED", "Authentication could not be completed.");
    public static ConflictException Conflict() => new("OPERATION_CONFLICT", "The operation conflicts with its previous binding.");
    public static ServiceUnavailableException Dependency() => new("DEPENDENCY_UNAVAILABLE", "An authoritative dependency is unavailable.");

    /// <summary>Rebuilds the category from a persisted outcome status (idempotent replay of a stored decision).</summary>
    public static BusinessException FromStatus(int status, string code) => status switch
    {
        400 => new BadRequestException(code), 401 => new UnauthorizedException(code), 403 => new ForbiddenException(code),
        404 => new NotFoundException(code), 409 => new ConflictException(code), 422 => new UnprocessableEntityException(code),
        503 => new ServiceUnavailableException(code),
        _ => throw new InvalidOperationException("A persisted outcome carries an unsupported status.")
    };
}
