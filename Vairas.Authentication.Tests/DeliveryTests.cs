using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using MimeKit;
using NUnit.Framework;
using Vairas.Authentication.Business;
using Vairas.Authentication.Configuration;
using Vairas.Authentication.Domain;
using Vairas.Authentication.Integrations;
using Vairas.Authentication.Persistance;
using Vairas.Authentication.Workers;

namespace Vairas.Authentication.Tests;

[TestFixture, NonParallelizable]
public sealed class DeliveryTests
{
    private readonly TestEnvironment env = new();
    [OneTimeSetUp] public Task Start() => env.StartAsync();
    [OneTimeTearDown] public async Task Stop() => await env.DisposeAsync();
    [SetUp] public Task Reset() => TestEnvironment.SqlAsync(env.OwnerConnection, "TRUNCATE challenge_delivery,auth_operation,security_event,oidc_request,account_challenge,refresh_token,auth_session,external_identity,password_credential,identity CASCADE");

    [TestCase("accepted", "Sent")]
    [TestCase("rejected", "Failed")]
    [TestCase("temporary", "Retry")]
    [TestCase("lost", "Unknown")]
    public async Task RealSmtpAdapterDistinguishesAcceptanceRejectionAndUncertainDataOutcome(string mode, string expected)
    {
        await using var server = new SmtpHarness(mode);
        var sender = new SmtpChallengeSender(new() { Host = "127.0.0.1", Port = server.Port, Security = "None",
            Sender = "auth@example.test", ChallengePage = "https://frontend.test/auth/challenge" });
        var secret = AuthPolicy.RandomSecret();
        var result = await sender.SendAsync(new("student@example.test", "VerifyEmail", secret), default);
        Assert.That(result.Status, Is.EqualTo(expected));
        if (expected == "Sent")
        {
            using var message = MimeMessage.Load(new MemoryStream(Encoding.UTF8.GetBytes(server.Message)));
            Assert.That(message.TextBody, Does.Contain("#challengeToken=" + secret).And.Contain("purpose=VerifyEmail"));
            Assert.That(message.To.Mailboxes.Single().Address, Is.EqualTo("student@example.test"));
        }
    }
    [Test]
    public async Task PreConnectFailureIsRetryable()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop();
        var sender = new SmtpChallengeSender(new() { Host = "127.0.0.1", Port = port, Security = "None", Sender = "auth@example.test", ChallengePage = "https://frontend.test/auth/challenge" });
        Assert.That((await sender.SendAsync(new("student@example.test", "ResetPassword", AuthPolicy.RandomSecret()), default)).Status, Is.EqualTo("Retry"));
    }
    [Test]
    public async Task ExpiredLeaseBecomesUnknownAndCannotBeAcknowledgedByTheOldWorker()
    {
        var email = Guid.NewGuid().ToString("N") + "@example.test";
        await env.Call(s => s.RegisterAsync(new(email, TestEnvironment.Password), TestEnvironment.Audit(), default));
        using var scope = env.Factory.Services.CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IDeliveryStore>();
        var item = (await store.ClaimAsync(default))!;
        Assert.That(item.Status, Is.EqualTo("Sending"));
        await using var db = env.OwnerDb();
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE challenge_delivery SET leased_until=clock_timestamp()-interval '1 second' WHERE delivery_id={item.DeliveryId}");
        Assert.That(await store.ClaimAsync(default), Is.Null);
        await store.CompleteAsync(item.DeliveryId, item.LeaseId!.Value, new("Sent"), default);
        var saved = await db.Set<ChallengeDelivery>().AsNoTracking().SingleAsync(d => d.DeliveryId == item.DeliveryId);
        Assert.That(saved.Status, Is.EqualTo("Unknown"));
        Assert.That(saved.ProtectedPayload, Is.Null);
    }
    [Test]
    public async Task KnownFailuresBackOffAndSuccessfulAcknowledgmentErasesThePayload()
    {
        var email = Guid.NewGuid().ToString("N") + "@example.test";
        await env.Call(s => s.RegisterAsync(new(email, TestEnvironment.Password), TestEnvironment.Audit(), default));
        using var scope = env.Factory.Services.CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IDeliveryStore>();
        var first = (await store.ClaimAsync(default))!;
        await store.CompleteAsync(first.DeliveryId, first.LeaseId!.Value, new("Retry", "SMTP_UNAVAILABLE"), default);
        Assert.That(await store.ClaimAsync(default), Is.Null);
        await using var db = env.OwnerDb();
        await db.Database.ExecuteSqlInterpolatedAsync($"UPDATE challenge_delivery SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE delivery_id={first.DeliveryId}");
        var retry = (await store.ClaimAsync(default))!;
        Assert.That(retry.Attempts, Is.EqualTo(2));
        await store.CompleteAsync(retry.DeliveryId, retry.LeaseId!.Value, new("Sent"), default);
        var saved = await db.Set<ChallengeDelivery>().AsNoTracking().SingleAsync(d => d.DeliveryId == first.DeliveryId);
        Assert.That(saved.Status, Is.EqualTo("Sent"));
        Assert.That(saved.ProtectedPayload, Is.Null);
    }
    [Test]
    public async Task ConsumedChallengesAreNotDispatched()
    {
        var email = Guid.NewGuid().ToString("N") + "@example.test";
        await env.Call(s => s.RegisterAsync(new(email, TestEnvironment.Password), TestEnvironment.Audit(), default));
        var mail = await env.MailAsync(email);
        await env.Call(s => s.CompleteAsync(new(mail.Token, null), TestEnvironment.Audit(), default));
        using var scope = env.Factory.Services.CreateScope();
        Assert.That(await scope.ServiceProvider.GetRequiredService<IDeliveryStore>().ClaimAsync(default), Is.Null);
        await using var db = env.OwnerDb();
        Assert.That((await db.Set<ChallengeDelivery>().SingleAsync()).Status, Is.EqualTo("Superseded"));
    }
    [Test]
    public async Task BackgroundWorkerSendsQueuedEncryptedPayloadThroughRealSmtpAdapter()
    {
        await using var smtp = new SmtpHarness("accepted");
        await using var test = new TestEnvironment(new()
        {
            ["Smtp:Host"] = "127.0.0.1", ["Smtp:Port"] = smtp.Port.ToString(), ["Smtp:Security"] = "None"
        });
        await test.StartAsync();
        var email = Guid.NewGuid().ToString("N") + "@example.test";
        await test.Call(s => s.RegisterAsync(new(email, TestEnvironment.Password), TestEnvironment.Audit(), default));
        using var worker = new ChallengeDeliveryWorker(test.Factory.Services.GetRequiredService<IServiceScopeFactory>(), new() { WorkerEnabled = true }, NullLogger<ChallengeDeliveryWorker>.Instance);
        await worker.StartAsync(default);
        try
        {
            var deadline = DateTimeOffset.UtcNow.AddSeconds(15);
            while (DateTimeOffset.UtcNow < deadline)
            {
                await using var db = test.OwnerDb();
                if (await db.Set<ChallengeDelivery>().AnyAsync(d => d.Status == "Sent" && d.ProtectedPayload == null)) break;
                await Task.Delay(100);
            }
            await using var final = test.OwnerDb();
            Assert.That((await final.Set<ChallengeDelivery>().SingleAsync()).Status, Is.EqualTo("Sent"));
        }
        finally { await worker.StopAsync(default); }
    }
}
