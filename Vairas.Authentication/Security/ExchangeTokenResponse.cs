using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration;
using Vairas.Delegation;

namespace Vairas.Authentication.Security;


/// <summary>Short-lived, school-bound read/preview delegation; never business execution.</summary>
public sealed record ExchangeTokenResponse(
    [property: System.Text.Json.Serialization.JsonPropertyName("access_token")] string AccessToken,
    [property: System.Text.Json.Serialization.JsonPropertyName("issued_token_type")] string IssuedTokenType,
    [property: System.Text.Json.Serialization.JsonPropertyName("token_type")] string TokenType,
    [property: System.Text.Json.Serialization.JsonPropertyName("expires_in")] int ExpiresIn,
    [property: System.Text.Json.Serialization.JsonPropertyName("scope")] string Scope);
