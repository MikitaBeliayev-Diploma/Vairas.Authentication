using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Text.Json;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration;
using Vairas.Authentication.Configuration.Options;

namespace Vairas.Authentication.Workers;

public sealed class ChallengeDeliveryWorker(IServiceScopeFactory scopes, SmtpOptions options, ILogger<ChallengeDeliveryWorker> logger) : BackgroundService
{
    private static readonly Meter Meter = new("Vairas.Authentication");
    private static readonly Counter<long> Deliveries = Meter.CreateCounter<long>("auth.challenge.deliveries");
    private static readonly ActivitySource Activities = new("Vairas.Authentication");
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.WorkerEnabled) return;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopes.CreateScope();
                var store = scope.ServiceProvider.GetRequiredService<IDeliveryStore>();
                var item = await store.ClaimAsync(stoppingToken);
                if (item is null) { await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken); continue; }
                using var activity = Activities.StartActivity("DeliverChallenge");
                activity?.SetTag("delivery.id", item.DeliveryId);
                DeliveryResult result;
                try
                {
                    if (!await store.IsCurrentAsync(item.ChallengeId, stoppingToken)) result = new("Superseded");
                    else
                    {
                        var payload = scope.ServiceProvider.GetRequiredService<ISecretProtector>().Unprotect("mail", item.ProtectedPayload!);
                        var mail = JsonSerializer.Deserialize<ChallengeMail>(payload) ?? throw new JsonException();
                        result = await scope.ServiceProvider.GetRequiredService<IChallengeSender>().SendAsync(mail, stoppingToken);
                    }
                }
                catch (Exception ex) when (ex is BusinessException or JsonException) { result = new("Failed", "PAYLOAD_UNAVAILABLE"); }
                await store.CompleteAsync(item.DeliveryId, item.LeaseId!.Value, result, stoppingToken);
                Deliveries.Add(1, new KeyValuePair<string, object?>("status", result.Status));
                logger.LogInformation("Challenge delivery {DeliveryId} completed with {DeliveryStatus} and {ErrorCode}", item.DeliveryId, result.Status, result.ErrorCode);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception)
            {
                // Do not log provider exception text: it may contain addresses or SMTP transcript material.
                logger.LogError("Challenge worker could not complete its iteration.");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }
    }
}
