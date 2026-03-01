using Arctium.Protocol.DNS.Model;
using System.Net;

namespace Arctium.Protocol.DNS
{
    public class DnsClientMessageIODoHRfc8484 : IDnsClientMessageIO
    {
        public readonly string ServerUri;

        public DnsClientMessageIODoHRfc8484(string serverUri)
        {
            if (string.IsNullOrWhiteSpace(serverUri)) throw new ArgumentException("serverUri is null or empty");

            ServerUri = serverUri;
        }

        public virtual Task<Message> QueryServerAsync(DnsClientMessageIOArg arg)
        {
            throw new NotImplementedException();
        }

        public static DnsClientMessageIODoHRfc8484 CreateDefault(string uri)
        {
            return new DnsClientMessageIODoHRfc8484(uri);
        }
    }
}
