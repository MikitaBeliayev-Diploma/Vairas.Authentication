using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

public interface IChallengeSender { Task<DeliveryResult> SendAsync(ChallengeMail mail, CancellationToken ct); }
