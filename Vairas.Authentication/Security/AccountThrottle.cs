using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Memory;
using Vairas.Authentication.Business;

namespace Vairas.Authentication.Security;

public sealed class AccountThrottle(TimeProvider clock) : IAccountThrottle, IDisposable
{
    private readonly MemoryCache cache = new(new MemoryCacheOptions { SizeLimit = 10000 });
    private readonly byte[] key = RandomNumberGenerator.GetBytes(32);
    private readonly object gate = new();
    public void Check(string normalizedEmail, string operation)
    {
        var id = Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(operation + ":" + normalizedEmail)));
        lock (gate)
        {
            var now = clock.GetUtcNow();
            var window = operation == "login" ? TimeSpan.FromMinutes(5) : TimeSpan.FromMinutes(15);
            var limit = operation == "login" ? 10 : 3;
            if (!cache.TryGetValue<Bucket>(id, out var bucket) || bucket is null || bucket.Until <= now)
            {
                bucket = new(now.Add(window));
                cache.Set(id, bucket, new MemoryCacheEntryOptions { AbsoluteExpiration = bucket.Until, Size = 1 });
            }
            if (++bucket.Count > limit) throw new TooManyRequestsException("RATE_LIMITED", "Try again later.");
        }
    }
    private sealed class Bucket(DateTimeOffset until) { public DateTimeOffset Until { get; } = until; public int Count { get; set; } }
    public void Dispose() { cache.Dispose(); CryptographicOperations.ZeroMemory(key); }
}
