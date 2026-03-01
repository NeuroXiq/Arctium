using Arctium.Protocol.DNS.Model;
using Arctium.Protocol.DNS.Protocol;
using Arctium.Shared;
using System.Diagnostics;
using System.Net;

namespace Arctium.Protocol.DNS
{
    public class DnsClientMessageIODoHRfc8484 : IDnsClientMessageIO
    {
        public readonly Func<DnsClientMessageIOArg, UriMethodResult> UriMethodSelect;
        public readonly bool HttpsRequired;
        public readonly HttpClient DnsHttpClient;
        public readonly bool RequiredHttps;
        DnsSerialize dnsSerialize = new DnsSerialize();

        public DnsClientMessageIODoHRfc8484(
            Func<DnsClientMessageIOArg, UriMethodResult> uriMethodSelect,
            HttpClient httpClient,
            bool requiredHttps)
        {
            if (uriMethodSelect == null) throw new ArgumentNullException(nameof(uriMethodSelect));
            if (httpClient == null) throw new ArgumentNullException(nameof(httpClient));
            if (requiredHttps == null) throw new ArgumentNullException(nameof(requiredHttps));

            UriMethodSelect = uriMethodSelect;
            DnsHttpClient = httpClient;
            RequiredHttps = requiredHttps;
        }

        public virtual async Task<Message> QueryServerAsync(DnsClientMessageIOArg arg)
        {
            UriMethodResult uriMethod = UriMethodSelect(arg);

            if (string.IsNullOrWhiteSpace(uriMethod.Uri)) throw new DnsException("Uri is null or empty");
            if (HttpsRequired && !uriMethod.Uri.ToLower().StartsWith("https://"))
                throw new DnsException($"configuration require https uri but it is not, current: '{uriMethod.Uri}'");


            var b64Message = Base64UrlEncodeMessage(arg.Message);

            DnsHttpClient.DefaultRequestHeaders.Add("Accept", "application/dns-message");
            var result = await DnsHttpClient.GetAsync($"{uriMethod.Uri}?dns={b64Message}");
            var body = await result.Content.ReadAsByteArrayAsync();

            var response = dnsSerialize.Decode(new BytesCursor(body));

            Debugger.Break();

            throw new Exception();
        }

        public string Base64UrlEncodeMessage(Message message)
        {
            ByteBuffer msgBytes = new ByteBuffer();
            dnsSerialize.Encode(message, msgBytes);

            string base64 = Convert.ToBase64String(msgBytes.Buffer, 0, msgBytes.Length);
            
            return base64.Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');
        }

        public static DnsClientMessageIODoHRfc8484 CreateDefault(Func<DnsClientMessageIOArg, UriMethodResult> uriMethodSelect)
        {
            return new DnsClientMessageIODoHRfc8484(uriMethodSelect, new HttpClient(), true);
        }

        public struct UriMethodResult
        {
            public string Uri;
            public string Method;
        }
    }
}
