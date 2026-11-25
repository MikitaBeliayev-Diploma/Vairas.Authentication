using Vairas.Authentication.Configuration;
using Vairas.Authentication.Middleware;
using Vairas.Authentication.Security;
using Vairas.Authentication.Startup;

if (StartupCommands.TryRun(args)) return;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.AddJsonLogging();
builder.Services
    .AddAuthenticationOptions(builder.Configuration)
    .AddJsonSerialization()
    .AddExceptionHandling()
    .AddOpenApiDocument()
    .AddAuthenticationServices()
    .AddSecretProtection()
    .AddAuthenticationDatabase()
    .AddIdentityProviderHttpClients()
    .AddChallengeDelivery()
    .AddBearerAuthentication()
    .AddWorkloadAuthorization()
    .AddBrowserCors()
    .AddPerAddressRateLimiting()
    .AddServiceHealthChecks()
    .AddServiceTelemetry(builder.Configuration);

var app = builder.Build();

// Fail fast: the signing keys are loaded and verified before the first request.
_ = app.Services.GetRequiredService<SigningKeys>();

app.UseMiddleware<CorrelationMiddleware>();
app.UseExceptionHandler();
app.UseStatusCodePages(context => ProblemResponses.WriteAsync(context.HttpContext, context.HttpContext.Response.StatusCode, "HTTP_ERROR", "The request could not be processed."));
app.UseRouting();
app.UseCors();
app.UseMiddleware<RequestGuardMiddleware>();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();
app.MapControllers();
app.MapOpenApiDocument();
app.MapServiceHealthChecks();
app.Run();

public partial class Program;
