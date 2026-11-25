using Vairas.Authentication.Security;

namespace Vairas.Authentication.Startup;

/// <summary>Local operator commands that run instead of the web host.</summary>
public static class StartupCommands
{
    /// <summary>`hash-secret`: reads a workload secret from stdin (never from arguments) and prints its Argon2id hash.</summary>
    public static bool TryRun(string[] args)
    {
        if (args is not ["hash-secret"])
            return false;
        var secret = Console.ReadLine();
        if (secret is null || secret.Length is < 32 or > 256)
            throw new ArgumentException("Supply a 32-256 character workload secret on stdin.");
        using var hasher = new PasswordHasher();
        Console.WriteLine(hasher.Hash(secret));
        return true;
    }
}
