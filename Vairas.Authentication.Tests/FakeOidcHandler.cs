using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using NUnit.Framework;
using Testcontainers.PostgreSql;
using Vairas.Authentication.Business;
using Vairas.Authentication.Domain;
using Vairas.Authentication.Persistance;
using Vairas.Authentication.Security;

namespace Vairas.Authentication.Tests;

public sealed class FakeOidcHandler : HttpMessageHandler
{
    private readonly RSA rsa = RSA.Create(2048);
    private readonly Dictionary<string, (string Nonce, string Challenge, string Redirect, string Subject, string Mode)> codes = [];
    public string Code(string authorizationUrl, string? subject = null, string mode = "valid")
    {
        var query = QueryHelpers.ParseQuery(new Uri(authorizationUrl).Query);
        var code = AuthPolicy.RandomSecret();
        codes.Add(code, (query["nonce"].ToString(), query["code_challenge"].ToString(), query["redirect_uri"].ToString(), subject ?? Guid.NewGuid().ToString("D"), mode));
        return code;
    }
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        if (request.RequestUri!.Host != "issuer.test") throw new HttpRequestException();
        if (request.RequestUri.AbsolutePath == "/.well-known/openid-configuration")
            return Json(new { issuer = "https://issuer.test", authorization_endpoint = "https://issuer.test/authorize", token_endpoint = "https://issuer.test/token", jwks_uri = "https://issuer.test/jwks", response_types_supported = new[] { "code" }, subject_types_supported = new[] { "public" }, id_token_signing_alg_values_supported = new[] { "RS256" } });
        if (request.RequestUri.AbsolutePath == "/jwks")
        {
            var p = rsa.ExportParameters(false);
            return Json(new { keys = new[] { new { kty = "RSA", use = "sig", alg = "RS256", kid = "external-test", n = Base64UrlEncoder.Encode(p.Modulus!), e = Base64UrlEncoder.Encode(p.Exponent!) } } });
        }
        var form = QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync(ct));
        if (!codes.Remove(form["code"].ToString(), out var value) || form["redirect_uri"] != value.Redirect || form["client_id"] != "test-client" ||
            form["client_secret"] != "test-client-secret" || Base64UrlEncoder.Encode(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(form["code_verifier"].ToString()))) != value.Challenge)
            return new(HttpStatusCode.BadRequest);
        if (value.Mode == "unavailable") return new(HttpStatusCode.ServiceUnavailable);
        var jwt = new JwtSecurityToken(value.Mode == "issuer" ? "https://evil.test" : "https://issuer.test", value.Mode == "audience" ? "other" : "test-client",
            [new("sub", value.Subject), new("nonce", value.Mode == "nonce" ? "wrong" : value.Nonce),
             new("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)],
            DateTime.UtcNow.AddMinutes(-10), DateTime.UtcNow.AddMinutes(value.Mode == "expired" ? -5 : 5),
            new SigningCredentials(new RsaSecurityKey(rsa) { KeyId = "external-test" }, "RS256"));
        return Json(new { id_token = new JwtSecurityTokenHandler().WriteToken(jwt), access_token = "synthetic-external", token_type = "Bearer", expires_in = 300 });
    }
    private static HttpResponseMessage Json(object value) => new(HttpStatusCode.OK) { Content = JsonContent.Create(value) };
    protected override void Dispose(bool disposing) { if (disposing) rsa.Dispose(); base.Dispose(disposing); }
}
