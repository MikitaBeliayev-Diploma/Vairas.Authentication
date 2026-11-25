namespace Vairas.Authentication.Domain;

public sealed class SecurityEvent
{
    public Guid EventId { get; set; }
    public Guid? IdentityId { get; set; }
    public Guid? SessionId { get; set; }
    public string EventType { get; set; } = "";
    public string OutcomeCode { get; set; } = "";
    public Guid CorrelationId { get; set; }
    public DateTimeOffset OccurredAt { get; set; }
}
