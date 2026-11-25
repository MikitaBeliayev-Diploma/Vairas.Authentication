namespace Vairas.Authentication.Configuration.Options;


public sealed class AuthOptions
{
    public string Issuer { get; set; } = "https://localhost:7100";
    public string UserAudience { get; set; } = "vairas-authentication";
    public string WorkloadAudience { get; set; } = "vairas-authentication-internal";
    public string[] UserAudiences { get; set; } = ["vairas-authentication", "vairas-user-management", "vairas-school-management", "vairas-vehicle-management", "vairas-scheduling", "vairas-learning-tracking", "vairas-notifications", "vairas-document-management", "vairas-chat"];
    public string? SigningCertificatePath { get; set; }
    public string? SigningCertificatePassword { get; set; }
    public string[] PreviousCertificates { get; set; } = [];
    public DelegationOptions Delegation { get; set; } = new();
    public Dictionary<string, WorkloadClientOptions> WorkloadClients { get; set; } = new(StringComparer.Ordinal);
    public Dictionary<string, string[]> ScopeAudiences { get; set; } = new(StringComparer.Ordinal)
    {
        ["mcp.lesson-actions.reconcile"] = ["vairas-mcp-internal"],
        ["scheduling.lesson-actions.reconcile"] = ["vairas-scheduling-internal"],
        ["chat.lesson-actions.authorize"] = ["vairas-chat-internal"],
        ["school.assistant.read"] = ["vairas-school-management-internal"],
        ["profiles.documents.read"] = ["vairas-user-management-internal"],
        ["school.documents.read"] = ["vairas-school-management-internal"],
        ["learning.documents.read"] = ["vairas-learning-tracking-internal"],
        ["learning.documents.decide"] = ["vairas-learning-tracking-internal"],
        ["identity.validate"] = ["vairas-authentication-internal"],
        ["identity.contact.read"] = ["vairas-authentication-internal"],
        ["school.notifications.read"] = ["vairas-school-management-internal"],
        ["scheduling.notifications.read"] = ["vairas-scheduling-internal"],
        ["learning.notifications.read"] = ["vairas-learning-tracking-internal"],
        ["profiles.status.read"] = ["vairas-user-management-internal"],
        ["profiles.contact.read"] = ["vairas-user-management-internal"],
        ["profiles.binding.read"] = ["vairas-user-management-internal"],
        ["profiles.deactivate"] = ["vairas-user-management-internal"],
        ["profiles.bootstrap"] = ["vairas-user-management-internal"],
        ["profiles.mcp.write"] = ["vairas-user-management-internal"],
        ["school.profile-provisioning"] = ["vairas-school-management-internal"],
        ["school.vehicle-authority.read"] = ["vairas-school-management-internal"],
        ["vehicles.eligibility.read"] = ["vairas-vehicle-management-internal"],
        ["scheduling.vehicle-gate"] = ["vairas-scheduling-internal"],
        ["scheduling.vehicle-blocks.write"] = ["vairas-scheduling-internal"],
        ["confirmations.validate"] = ["vairas-chat-internal"]
        ,["school.learning.read"] = ["vairas-school-management-internal"]
        ,["school.participants.read"] = ["vairas-school-management-internal"]
        ,["school.scheduling.read"] = ["vairas-school-management-internal"]
        ,["school.coordination.read"] = ["vairas-school-management-internal"]
        ,["school.eligibility.read"] = ["vairas-school-management-internal"]
        ,["scheduling.source.read"] = ["vairas-scheduling-internal"]
        ,["scheduling.school-gate"] = ["vairas-scheduling-internal"]
        ,["learning.planning.read"] = ["vairas-learning-tracking-internal"]
        ,["learning.readiness.read"] = ["vairas-learning-tracking-internal"]
        ,["learning.programmes.read"] = ["vairas-learning-tracking-internal"]
        ,["learning.evidence.read"] = ["vairas-learning-tracking-internal"]
    };
    public string[] BrowserOrigins { get; set; } = [];
    public string OidcCookieSameSite { get; set; } = "Lax";
    public Dictionary<string, OidcProviderOptions> OidcProviders { get; set; } = new(StringComparer.Ordinal);
}
