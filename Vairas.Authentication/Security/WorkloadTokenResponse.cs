using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration;

namespace Vairas.Authentication.Security;


/// <summary>OAuth2 client-credentials result, using the standard field names.</summary>
public sealed record WorkloadTokenResponse(
    [property: System.Text.Json.Serialization.JsonPropertyName("access_token")] string AccessToken,
    [property: System.Text.Json.Serialization.JsonPropertyName("token_type")] string TokenType,
    [property: System.Text.Json.Serialization.JsonPropertyName("expires_in")] int ExpiresIn,
    [property: System.Text.Json.Serialization.JsonPropertyName("scope")] string Scope,
    [property: System.Text.Json.Serialization.JsonPropertyName("issued_token_type"), System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? IssuedTokenType = null);
