using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

public interface IAuthStore
{
    Task<T> ExecuteAsync<T>(Func<IAuthTransaction, Task<T>> action, CancellationToken ct);
}
