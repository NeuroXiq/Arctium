using Arctium.Protocol.DNS.Model;
using Arctium.Protocol.DNS.Protocol;
using Arctium.Shared;
using System.Diagnostics;
using System.Net;

namespace Arctium.Protocol.DNS
{
    public class DnsClientMessageIO_Rfc8484DoH : IDnsClientMessageIO
    {
        public readonly string HttpsUriFormat;
        public readonly bool HttpsRequired;
        public readonly HttpClient DnsHttpClient;
        public readonly bool RequiredHttps;
        public readonly HttpMethod Method;
        DnsSerialize dnsSerialize = new DnsSerialize();

        public DnsClientMessageIO_Rfc8484DoH(
            string httpsUri,
            HttpClient httpClient,
            HttpMethod method)
        {
            if (string.IsNullOrWhiteSpace(httpsUri) || !httpsUri.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("httpsUri is empty or not start with 'https'");
            if (httpClient == null) throw new ArgumentNullException(nameof(httpClient));
            if (!Enum.IsDefined(method)) throw new ArgumentException("method");

            if (method == HttpMethod.Get && !httpsUri.Contains("{0}"))
            {
                throw new ArgumentException("for get requests https uri must contain format parameter '{0}' to format query string");
            }

            if (method == HttpMethod.Post && httpsUri.Contains("{0}"))
            {
                throw new ArgumentException("for post requests https uri must not contain format parameter '{0}' to format query string");
            }

            HttpsUriFormat = httpsUri;
            DnsHttpClient = httpClient;
            Method = method;
        }

        public virtual async Task<Message> QueryServerAsync(DnsClientMessageIOArg arg)
        {
            HttpResponseMessage result;
            byte[] body;

            if (Method == HttpMethod.Get)
            {
                string b64Message = dnsSerialize.EncodeDohForGet(arg.Message);
                result = await DnsHttpClient.GetAsync(string.Format(HttpsUriFormat, b64Message));
                body = await result.Content.ReadAsByteArrayAsync();
            }
            else
            {
                ByteBuffer msgBytes = new ByteBuffer();
                dnsSerialize.EncodeDohForPost(arg.Message, msgBytes);

                var httpRequest = new HttpRequestMessage(System.Net.Http.HttpMethod.Post, HttpsUriFormat);
                httpRequest.Content = new ByteArrayContent(msgBytes.Buffer, 0, msgBytes.Length);
                httpRequest.Content.Headers.Add("content-type", "application/dns-message");

                result = await DnsHttpClient.SendAsync(httpRequest);
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
