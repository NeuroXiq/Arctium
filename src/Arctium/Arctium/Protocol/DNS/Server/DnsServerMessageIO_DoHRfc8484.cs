using Arctium.Protocol.DNS.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Protocol.DNS.Server
{
    public class DnsServerMessageIO_DoHRfc8484 : IDnsServerMessageIOAdapter
    {
        protected Func<Message, Task<Message>> serverProcessMessage;
        protected CancellationToken serverStopCancellationToken;
        protected HttpListener httpListener;
        protected Task task;
        protected WebApplication kestrelWebApplication;
        protected string appUrl;
        protected X509Certificate2 x509Certificate;
        protected string mapGetPath;
        protected string mapPostPath;
        protected string getPathQueryParamName;

        public DnsServerMessageIO_DoHRfc8484() { }

        public DnsServerMessageIO_DoHRfc8484(
            string appUrl,
            string mapGetPath,
            string getPathQueryParamName,
            string mapPostPath,
            X509Certificate2 x509Certificate)
        {
            this.appUrl = appUrl;
            this.x509Certificate = x509Certificate;
            this.mapGetPath = mapGetPath;
            this.mapPostPath = mapPostPath;
            this.getPathQueryParamName = getPathQueryParamName;
        }

        public void Configure(Func<Message, Task<Message>> serverProcessMessage, CancellationToken serverStopCancellationToken)
        {
            this.serverProcessMessage = serverProcessMessage;
            this.serverStopCancellationToken = serverStopCancellationToken;
        }

        /// <summary>
        /// This method should be overriden and then create custom implementation of http server
        /// </summary>
        public virtual void OnServerStart()
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
                app.MapGet("/", OnGetRequestReceived);
            }

            if (!string.IsNullOrWhiteSpace(mapGetPath))
            {
                app.MapPost("/", this.OnPostRequestReceived);
            }

            task = Task.Run(async () => await app.RunAsync());
        }

        public virtual void OnServerStop()
        {
            kestrelWebApplication.StopAsync().Wait();
        }

        protected async Task OnPostRequestReceived(HttpContext context)
        {
            Debugger.Break();
        }

        protected async Task OnGetRequestReceived(HttpContext context)
        {

            if (context.Request.Query.TryGetValue(this.getPathQueryParamName, out var values))
            {
                context.Response.StatusCode = 200;
            }
            else
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "text/html";
                string msg = $"client send invalid request to server. it does not contain required query parameter: '{this.getPathQueryParamName}'";
                string html = "<html>";
                html += "<head></head>";
                html += $"<body>{msg}</body>";
                html += "<html>";
                
                await context.Response.WriteAsync(html);
            }

        }
    }
}
