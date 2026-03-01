using Arctium.Protocol.DNS.Model;
using System.Net;

namespace Arctium.Protocol.DNS
{
    public class DnsClientMessageIODoHRfc8484 : IDnsClientMessageIO
    {
        public readonly Func<DnsClientMessageIOArg, UriMethodResult> UriMethodSelect;
        public readonly bool HttpsRequired;
        public readonly HttpClient DnsHttpClient;
        public readonly bool RequiredHttps;

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

        public virtual Task<Message> QueryServerAsync(DnsClientMessageIOArg arg)
        {
            UriMethodResult uriMethod = UriMethodSelect(arg);

            if (string.IsNullOrWhiteSpace(uriMethod.Uri)) throw new DnsException("Uri is null or empty");
            if (HttpsRequired && !uriMethod.Uri.ToLower().StartsWith("https://"))
                throw new DnsException($"configuration require https uri but it is not, current: '{uriMethod.Uri}'");


        }

        public static DnsClientMessageIODoHRfc8484 CreateDefault(Func<DnsClientMessageIOArg, UriMethodResult> uriMethodSelect)
        {
            return new DnsClientMessageIODoHRfc8484(uriMethodSelect);
        }

        public struct UriMethodResult
        {
            public string Uri;
            public string Method;
        }
    }
}
