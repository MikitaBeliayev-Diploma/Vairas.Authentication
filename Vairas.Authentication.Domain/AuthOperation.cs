namespace Vairas.Authentication.Domain;

public sealed class AuthOperation
{
    public Guid OperationId { get; set; }
    public Guid IdentityId { get; set; }
    public Guid SourceSessionId { get; set; }
    public Guid TargetSessionId { get; set; }
    public string Fingerprint { get; set; } = "";
    public int OutcomeStatus { get; set; } = 200;
    public DateTimeOffset RecordedAt { get; set; }
}
