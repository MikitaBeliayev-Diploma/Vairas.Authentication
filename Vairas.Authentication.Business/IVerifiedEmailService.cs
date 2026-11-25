using System.Security.Cryptography;
using System.Text;

namespace Vairas.Authentication.Business;

public interface IVerifiedEmailService { Task<VerifiedEmailResponse> ReadAsync(Guid identity, CancellationToken ct); }
