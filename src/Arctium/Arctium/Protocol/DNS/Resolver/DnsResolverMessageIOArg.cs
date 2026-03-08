using Arctium.Protocol.DNS.Model;
using System.Net;

namespace Arctium.Protocol.DNS.Resolver
{
    public struct DnsResolverMessageIOArg
    {
        public string NSDName;
        public IPAddress IpAddress;
        public Message Message;

        public DnsResolverMessageIOArg(string nsdName, IPAddress ipAddress, Message message)
        {
            NSDName = nsdName;
            IpAddress = ipAddress;
            Message = message;
        }
    }
}
