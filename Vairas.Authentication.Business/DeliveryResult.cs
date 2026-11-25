using Vairas.Authentication.Domain;

namespace Vairas.Authentication.Business;

public sealed record DeliveryResult(string Status, string? ErrorCode = null);
