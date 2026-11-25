using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration;

namespace Vairas.Authentication.Security;


public interface IWorkloadTokenService
{
    WorkloadTokenResponse Issue(string grant, string client, string secret, string scope);
    bool Allowed(ClaimsPrincipal caller, string requiredScope);
}
