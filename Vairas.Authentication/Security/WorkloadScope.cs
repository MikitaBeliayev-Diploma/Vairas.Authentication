using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration;
using Vairas.Authentication.Middleware;

namespace Vairas.Authentication.Security;


public sealed record WorkloadScope(string Scope) : IAuthorizationRequirement;
