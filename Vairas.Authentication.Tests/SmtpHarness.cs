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

public sealed class SmtpHarness : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stopping = new();
    private readonly Task loop;
    public int Port { get; }
    public string Message { get; private set; } = "";
    public SmtpHarness(string mode)
    {
        listener.Start(); Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        loop = Task.Run(async () =>
        {
            try
            {
                using var client = await listener.AcceptTcpClientAsync(stopping.Token);
                await using var stream = client.GetStream();
                using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
                await using var writer = new StreamWriter(stream, Encoding.ASCII, leaveOpen: true) { AutoFlush = true, NewLine = "\r\n" };
                await writer.WriteLineAsync("220 localhost test SMTP");
                while (!stopping.IsCancellationRequested)
                {
                    var line = await reader.ReadLineAsync(stopping.Token);
                    if (line is null) break;
                    if (line.StartsWith("EHLO", StringComparison.Ordinal)) { await writer.WriteLineAsync("250-localhost"); await writer.WriteLineAsync("250 PIPELINING"); }
                    else if (line == "DATA")
                    {
                        await writer.WriteLineAsync("354 End data with <CRLF>.<CRLF>");
                        var body = new StringBuilder();
                        while ((line = await reader.ReadLineAsync(stopping.Token)) is not null && line != ".") body.AppendLine(line.StartsWith("..", StringComparison.Ordinal) ? line[1..] : line);
                        Message = body.ToString();
                        if (mode == "lost") { client.Close(); break; }
                        await writer.WriteLineAsync(mode == "rejected" ? "550 Rejected" : mode == "temporary" ? "451 Try later" : "250 Accepted");
                    }
                    else if (line == "QUIT") { await writer.WriteLineAsync("221 Bye"); break; }
                    else await writer.WriteLineAsync("250 OK");
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or IOException or SocketException) { }
        });
    }
    public async ValueTask DisposeAsync() { await stopping.CancelAsync(); listener.Stop(); await loop; stopping.Dispose(); }
}
