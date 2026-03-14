using Arctium.Protocol.DNS.Model;
using Arctium.Protocol.DNS.Protocol;
using Arctium.Shared;
using System.Diagnostics;
using System.Net;
using System.Web;

namespace Arctium.Protocol.DNS.Resolver
{
    public class DnsResolverMessageIO_Rfc8484DoH : IDnsResolverMessageIO
    {
        public readonly string httpsUriFormat;
        public readonly bool httpsRequired;
        public readonly HttpClient dnsHttpClient;
        public readonly bool requiredHttps;
        public readonly HttpMethod method;
        DnsSerialize dnsSerialize = new DnsSerialize();

        public DnsResolverMessageIO_Rfc8484DoH(
            string httpsUri,
            HttpMethod method,
            HttpClient httpClient) 
        {
            if (string.IsNullOrWhiteSpace(httpsUri) || !httpsUri.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("httpsUri is empty or not start with 'https'");
            if (httpClient == null) throw new ArgumentNullException(nameof(httpClient));
            if (!Enum.IsDefined(method)) throw new ArgumentException("method");
            if (!Uri.IsWellFormedUriString(httpsUri, UriKind.Absolute)) throw new ArgumentException("httpsUri is not valid url");

            if (method == HttpMethod.Get && !httpsUri.Contains("{0}"))
            {
                throw new ArgumentException("for get requests httpsUri must not be empty, and must contain '{0}' format string somewhere");
            }

            if (method == HttpMethod.Post && httpsUri.Contains("{0}"))
            {
                throw new ArgumentException("for post requests https uri must not contain format parameter '{0}' to format query string");
            }

            this.dnsHttpClient = httpClient;
            this.method = method;
            this.httpsUriFormat = httpsUri;
        }

        public DnsResolverMessageIO_Rfc8484DoH(
            string httpsUri,
            HttpMethod method) : this(httpsUri, method, CreateDefaultHttpClient())
        {
        }

        public static HttpClient CreateDefaultHttpClient()
        {
            var client = new HttpClient();
            client.DefaultRequestHeaders.Add("Accept", "application/dns-message");

            return client;
        }

        public virtual async Task<Message> QueryServerAsync(DnsResolverMessageIOArg arg)
        {
            HttpResponseMessage result;
            byte[] body;

            if (method == HttpMethod.Get)
            {
                string b64Message = dnsSerialize.EncodeDohForGet(arg.Message);
                string getUrl = string.Format(httpsUriFormat, b64Message);
                result = await dnsHttpClient.GetAsync(getUrl);
                body = await result.Content.ReadAsByteArrayAsync();
            }
            else
            {
                ByteBuffer msgBytes = new ByteBuffer();
                dnsSerialize.EncodeDohForPost(arg.Message, msgBytes);

                var httpRequest = new HttpRequestMessage(System.Net.Http.HttpMethod.Post, httpsUriFormat)
                {
                };

                httpRequest.Content = new ByteArrayContent(msgBytes.Buffer, 0, msgBytes.Length);
                httpRequest.Content.Headers.Add("content-type", "application/dns-message");

                result = await dnsHttpClient.SendAsync(httpRequest);
            }

            result.EnsureSuccessStatusCode();
            body = await result.Content.ReadAsByteArrayAsync();
            
            var response = dnsSerialize.Decode(new BytesCursor(body));

            return response;
        }

        public enum HttpMethod
        {
            Get = 1,
            Post = 2
        }
    }
}
