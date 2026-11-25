using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;
using Vairas.Authentication.Configuration.Options;

namespace Vairas.Authentication.Configuration;

public sealed class ApiDocumentTransformer(AuthOptions settings) : IOpenApiDocumentTransformer
{
    public Task TransformAsync(OpenApiDocument document, OpenApiDocumentTransformerContext context, CancellationToken ct)
    {
        document.Info.Title = "Vairas Authentication API";
        document.Info.Version = "1.0.0";
        document.Info.Description = "Global identity, verified local credentials, browser-bound external OIDC login/link, sessions and scoped workload tokens. " +
            "No profiles or school roles are created. Registration/challenge acknowledgments do not disclose account existence. " +
            "User access tokens last at most 15 minutes; refresh tokens rotate once. Email links are delivered asynchronously through SMTP.";
        document.Components ??= new();
        document.Components.SecuritySchemes = new Dictionary<string, IOpenApiSecurityScheme>
        {
            ["bearerAuth"] = new OpenApiSecurityScheme { Type = SecuritySchemeType.Http, Scheme = "bearer", BearerFormat = "JWT" },
            ["workloadOAuth"] = new OpenApiSecurityScheme { Type = SecuritySchemeType.OAuth2, Flows = new()
            {
                ClientCredentials = new() { TokenUrl = new Uri(settings.Issuer + "/connect/token"),
                    Scopes = new Dictionary<string, string> { ["identity.validate"] = "Validate current identity and exact session ownership", ["identity.contact.read"] = "Read verified login email for Notifications" } }
            } }
        };
        document.Components.Schemas ??= new Dictionary<string, IOpenApiSchema>();
        document.Components.Schemas["AuthProblem"] = new OpenApiSchema
        {
            Type = JsonSchemaType.Object, Required = new HashSet<string> { "title", "status", "code", "correlationId" },
            Properties = new Dictionary<string, IOpenApiSchema>
            {
                ["title"] = new OpenApiSchema { Type = JsonSchemaType.String }, ["status"] = new OpenApiSchema { Type = JsonSchemaType.Integer },
                ["code"] = new OpenApiSchema { Type = JsonSchemaType.String }, ["correlationId"] = new OpenApiSchema { Type = JsonSchemaType.String }
            }
        };
        foreach (var name in new[] { "CredentialsRequest", "RefreshRequest", "ChallengeCompletionRequest", "OidcCallbackRequest", "WorkloadTokenRequest" })
            if (document.Components.Schemas.TryGetValue(name, out var schema) && schema.Properties is not null)
                foreach (var (property, definition) in schema.Properties)
                    if (property is "password" or "refreshToken" or "challengeToken" or "newPassword" or "code" or "state" or "client_secret" or "subject_token" && definition is OpenApiSchema secret)
                        secret.WriteOnly = true;
        var operations = new Dictionary<string, string>
        {
            ["/internal/v1/identities/{identityId}/verified-email"] = "getVerifiedNotificationEmail",
            ["/connect/token"] = "acquireUserManagementWorkloadToken", ["/internal/v1/sessions/validate"] = "validateUserManagementSession",
            ["/api/v1/auth/registrations"] = "registerIdentity", ["/api/v1/auth/login"] = "loginIdentity", ["/api/v1/auth/refresh"] = "rotateRefreshToken",
            ["/api/v1/auth/challenges"] = "requestAccountChallenge", ["/api/v1/auth/challenges/completion"] = "completeAccountChallenge",
            ["/api/v1/auth/oidc/requests"] = "beginOidc", ["/api/v1/auth/oidc/callback"] = "completeOidc",
            ["/api/v1/auth/sessions/{sessionId}/revocation"] = "revokeOwnSession", ["/.well-known/openid-configuration"] = "getIssuerDiscovery",
            ["/.well-known/jwks.json"] = "getSigningKeys"
        };
        foreach (var (path, item) in document.Paths)
        foreach (var operation in item.Operations!.Values)
        {
            operation.OperationId = operations[path];
            if (path == "/connect/token") operation.Description = "Internal client_credentials or explicitly enabled RFC 8693 ReadPreviewV1 exchange. Exchange requires subject_token/access-token type, one configured resource, school_id and a subset of read/preview scopes. Only chat-backend -> MCP -> owner is permitted; ConfirmedLessonActionsV1 additionally requires its separate enable switch and exact lesson_action binding; its second hop targets Scheduling only. No refresh token grant. Exchange success additionally returns issued_token_type. Never publish this endpoint through Gateway.";
            operation.Security = [];
            if (path.StartsWith("/internal/", StringComparison.Ordinal)) operation.Security = [new() { [new OpenApiSecuritySchemeReference("workloadOAuth", document)] = [path.EndsWith("/verified-email", StringComparison.Ordinal) ? "identity.contact.read" : "identity.validate"] }];
            else if (path.EndsWith("/revocation", StringComparison.Ordinal)) operation.Security = [new() { [new OpenApiSecuritySchemeReference("bearerAuth", document)] = [] }];
            operation.Responses ??= new();
            foreach (var status in new[] { "400", "401", "403", "404", "409", "415", "429", "500", "503" })
            {
                if (path.StartsWith("/.well-known/", StringComparison.Ordinal) && status is not "500") continue;
                operation.Responses[status] = new OpenApiResponse { Description = "Non-disclosing error; preserve code and correlationId.",
                    Content = new Dictionary<string, OpenApiMediaType> { ["application/problem+json"] = new() { Schema = new OpenApiSchemaReference("AuthProblem", document) } } };
            }
            if (path.Contains("/oidc/", StringComparison.Ordinal)) operation.Description = "Requires a Secure HttpOnly browser correlation cookie. " +
                "The frontend forwards code/state by JSON POST after the allowlisted provider redirect. Link additionally requires a currently active user bearer session. " +
                "Transactions are single-use and expire after ten minutes; matching email never authorizes linking.";
            if (path.EndsWith("/revocation", StringComparison.Ordinal))
            {
                ((OpenApiParameter)operation.Parameters!.Single(p => p.Name == "Idempotency-Key")).Required = true;
                operation.Description = "Only the identity's own sessions. Successful and authenticated not-found outcomes retain the key binding; changed target/identity conflicts. " +
                    "A completed self-logout can replay its saved receipt with the original still-unexpired JWT; this exception authorizes no other action.";
            }
            foreach (var response in operation.Responses.Values) response.Content?.Remove("text/plain");
        }
        return Task.CompletedTask;
    }
}
