using System.Security.Cryptography;
using Isopoh.Cryptography.Argon2;
using Microsoft.AspNetCore.DataProtection;
using Vairas.Authentication.Business;

namespace Vairas.Authentication.Security;


public sealed class PasswordHasher : IPasswordHasher, IDisposable
{
    private readonly SemaphoreSlim slots = new(2, 2);
    private readonly string dummy;
    public PasswordHasher() => dummy = Hash(AuthPolicy.RandomSecret());
    public string Hash(string password)
    {
        if (!slots.Wait(0)) throw new TooManyRequestsException("RATE_LIMITED", "Try again later.");
        try
        {
            return Argon2.Hash(password, timeCost: 3, memoryCost: 65536, parallelism: 1, type: Argon2Type.HybridAddressing);
        }
        finally { slots.Release(); }
    }
    public bool Verify(string hash, string password)
    {
        if (!slots.Wait(0)) throw new TooManyRequestsException("RATE_LIMITED", "Try again later.");
        try { return Argon2.Verify(hash, password); }
        catch (Exception ex) when (ex is ArgumentException or FormatException or IndexOutOfRangeException) { return false; }
        finally { slots.Release(); }
    }
    public void DummyVerify(string password) => Verify(dummy, password);
    public void Dispose() => slots.Dispose();
}
