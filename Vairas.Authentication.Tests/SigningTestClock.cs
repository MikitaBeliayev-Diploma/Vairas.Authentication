using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Moq;
using NUnit.Framework;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration;
using Vairas.Authentication.Security;
using Vairas.Authentication.Configuration.Options;

namespace Vairas.Authentication.Tests;

internal sealed class SigningTestClock(DateTimeOffset current) : TimeProvider
{
    public DateTimeOffset Current { get; set; } = current;
    public override DateTimeOffset GetUtcNow() => Current;
}
