namespace Vairas.Authentication.Configuration.Options;

/// <summary>Bound from "RateLimits": optional override of the per-IP request budget for the public and token policies.</summary>
public sealed class RateLimitOptions
{
    public int? RequestsPerMinute { get; set; }
}
