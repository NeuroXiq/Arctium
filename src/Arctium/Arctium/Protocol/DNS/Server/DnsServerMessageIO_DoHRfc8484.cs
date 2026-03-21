using Arctium.Protocol.DNS.Model;
using Arctium.Protocol.DNS.Protocol;
using Arctium.Shared;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Protocol.DNS.Server
{
    public class DnsServerMessageIO_DoHRfc8484 : IDnsServerMessageIOAdapter
    {
        protected Task task;
        protected WebApplication app;
        private string appUrl;
        private string mapGetPath;
        private string mapPostPath;
        private X509Certificate2 x509Certificate;
        protected DnsSerialize dnsSerialize;
        private OnServerStartParams onServerStartParams;

        public DnsServerMessageIO_DoHRfc8484(
            string appUrl,
            string getUriPath,
            string postUriPath,
            X509Certificate2 x509Certificate)
        {
            this.appUrl = appUrl;
            this.mapGetPath = getUriPath;
            this.mapPostPath = postUriPath;
            this.x509Certificate = x509Certificate;

            dnsSerialize = new DnsSerialize();
        }

        protected virtual WebApplication CreateDefaultKestrelServer()
        {
            var builder = WebApplication.CreateBuilder();

            builder.WebHost.ConfigureKestrel(c =>
            {
                c.ConfigureHttpsDefaults(httpsOptions =>
                {
                    httpsOptions.ServerCertificate = x509Certificate;
                });
            });

            var app = builder.Build();

            app.Urls.Add(appUrl);

            if (!string.IsNullOrWhiteSpace(mapGetPath))
            {
                app.MapGet(mapGetPath, OnGetRequestReceived);
            }

            if (!string.IsNullOrWhiteSpace(mapGetPath))
            {
                app.MapPost(mapPostPath, OnPostRequestReceived);
            }

            return app;
        }

        /// <summary>
        /// This method should be overriden and then create custom implementation of http server
        /// </summary>
        public virtual void OnServerStart(OnServerStartParams onServerStartParams)
        {
            this.onServerStartParams = onServerStartParams;
            app = this.CreateDefaultKestrelServer();

            task = Task.Run(async () => await app.RunAsync());
        }

        public virtual void OnServerStop()
        {
            app.StopAsync().Wait();
        }

        public virtual async Task OnPostRequestReceived(HttpContext context)
        {
            byte[] dnsMessageBytes;
            Message clientMessage;

            try
            {
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    await context.Request.Body.CopyToAsync(memoryStream);
                    dnsMessageBytes = memoryStream.ToArray();
                }

                clientMessage = dnsSerialize.Decode(dnsMessageBytes);

                await ProcessClientDnsMessageBytes(context, clientMessage);
            }
            catch (Exception e)
            {
               await OnException(context, e);
            }
        }

        public virtual async Task OnGetRequestReceived(HttpContext context, [FromQuery] string dns)
        {
            try
            {
                if (context.Request.Headers.TryGetValue("accept", out var acceptValues)
                    && acceptValues.Count == 1 
                    && !string.IsNullOrWhiteSpace(dns))
                {
                    Message clientMessage = dnsSerialize.Decode_DohFromGet(dns);

                    await ProcessClientDnsMessageBytes(context, clientMessage);
                }
                else
                {
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "text/html";
                    string msg =
                        "client send invalid request to server. it does not contain " +
                        $"required query parameter: '?dns=...' " +
                        "or parameter count is invalid (should be 1 parameter) or request " + 
                        "does not have 'accept: application/dns-message header set";
                    string html = "<html>";
                    html += "<head></head>";
                    html += $"<body>{msg}</body>";
                    html += "<html>";

                    await context.Response.WriteAsync(html, onServerStartParams.ServerStopCancellationToken);
                }
            }
            catch (Exception e)
            {
                await OnException(context, e);
            }
        }

        protected virtual async Task ProcessClientDnsMessageBytes(HttpContext context, Message clientMessage)
        {
            var dnsContext = new DnsRequestContext(clientMessage);
            await onServerStartParams.Next.Next(dnsContext);
            Message serverMessage = dnsContext.ServerMessage;
            ByteBuffer responseBytes = new ByteBuffer();

            dnsSerialize.EncodeRaw(serverMessage, responseBytes);

            context.Response.StatusCode = 200;
            context.Response.Headers.Append("content-type", "application/dns-message");
            await context.Response.BodyWriter.WriteAsync(responseBytes.ToReadOnlyMemory());
        }

        protected virtual async Task OnException(HttpContext context, Exception e)
        {
            try
            {
                context.Response.StatusCode = 500;
                await context.Response.WriteAsync("server error");
            }
            catch (Exception ignore)
            {
            }
        }
    }
}
