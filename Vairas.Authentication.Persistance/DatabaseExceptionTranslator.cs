using Microsoft.EntityFrameworkCore;
using Npgsql;
using Vairas.Authentication.Business;

namespace Vairas.Authentication.Persistance;

/// <summary>
/// Translates provider-specific failures to application exceptions at the persistence boundary, so the API layer never
/// classifies EF Core, Npgsql or SQLSTATE values. Original exceptions are kept as inner exceptions for diagnostics.
/// </summary>
public static class DatabaseExceptionTranslator
{
    /// <summary>
    /// Constraints whose violation is an expected business outcome. Anything else that fires a foreign-key or check
    /// constraint is treated as an unexpected integrity failure (see <see cref="PersistenceFailureException"/>).
    /// </summary>
    private static readonly HashSet<string> BusinessConstraints = new(StringComparer.Ordinal);

    public static Exception? Translate(Exception exception)
    {
        if (exception is OperationCanceledException or BusinessException or PersistenceFailureException)
            return null;
        var postgres = exception as PostgresException ?? (exception as DbUpdateException)?.InnerException as PostgresException;
        if (postgres is not null)
            return postgres.SqlState switch
            {
                PostgresErrorCodes.SerializationFailure or PostgresErrorCodes.DeadlockDetected or PostgresErrorCodes.LockNotAvailable =>
                    new ServiceUnavailableException("DEPENDENCY_UNAVAILABLE", "The database is unavailable.", exception),
                PostgresErrorCodes.ForeignKeyViolation or PostgresErrorCodes.CheckViolation when postgres.ConstraintName is { } name && BusinessConstraints.Contains(name) =>
                    new ConflictException("BUSINESS_RULE_REJECTED", "The command violates a business rule.", exception),
                _ => new PersistenceFailureException(postgres.SqlState, postgres.ConstraintName, exception)
            };
        if (exception is NpgsqlException { IsTransient: true })
            return new ServiceUnavailableException("DEPENDENCY_UNAVAILABLE", "The database is unavailable.", exception);
        if (exception is DbUpdateException)
            return new PersistenceFailureException(null, null, exception);
        return null;
    }

    /// <summary>Runs a database operation and throws the translated exception when the failure is recognised.</summary>
    public static async Task<T> GuardAsync<T>(Func<Task<T>> operation)
    {
        try { return await operation(); }
        catch (Exception e) when (Translate(e) is not null) { throw Translate(e)!; }
    }

    public static async Task GuardAsync(Func<Task> operation)
    {
        try { await operation(); }
        catch (Exception e) when (Translate(e) is not null) { throw Translate(e)!; }
    }
}
