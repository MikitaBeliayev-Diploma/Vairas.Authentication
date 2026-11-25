namespace Vairas.Authentication.Business;

/// <summary>A per-address or per-account attempt limit was exceeded; the caller retries later.</summary>
public sealed class TooManyRequestsException(string code, string message = BusinessException.DefaultMessage, Exception? innerException = null)
    : BusinessException(code, message, innerException);
