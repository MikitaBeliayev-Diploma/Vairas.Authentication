using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

public interface IDeliveryStore
{
    Task<ChallengeDelivery?> ClaimAsync(CancellationToken ct);
    Task CompleteAsync(Guid deliveryId, Guid leaseId, DeliveryResult result, CancellationToken ct);
    Task<bool> IsCurrentAsync(Guid challengeId, CancellationToken ct);
}
