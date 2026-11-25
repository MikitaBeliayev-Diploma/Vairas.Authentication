namespace Vairas.Authentication.Domain;

public sealed class ChallengeDelivery
{
    public Guid DeliveryId { get; set; }
    public Guid ChallengeId { get; set; }
    public string? ProtectedPayload { get; set; }
    public string Status { get; set; } = "Pending";
    public int Attempts { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset NextAttemptAt { get; set; }
    public Guid? LeaseId { get; set; }
    public DateTimeOffset? LeasedUntil { get; set; }
    public string? LastErrorCode { get; set; }
}
