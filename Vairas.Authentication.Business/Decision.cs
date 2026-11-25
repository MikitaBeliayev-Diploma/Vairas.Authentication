using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

public sealed record Decision<T>(T? Value, BusinessException? Error) where T : class
{
    public T Get() => Error is not null ? throw Error : Value!;
    public static Decision<T> Allow(T value) => new(value, null);
    public static Decision<T> Deny(BusinessException? error = null) => new(null, error ?? AuthErrors.Denied());
}
