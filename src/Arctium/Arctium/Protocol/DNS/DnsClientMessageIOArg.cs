using Arctium.Protocol.DNS.Model;
using System.Net;

namespace Arctium.Protocol.DNS
{
    public struct DnsClientMessageIOArg
    {
        public string NSDName;
        public IPAddress IpAddress;
        public Message Message;

        public DnsClientMessageIOArg(string nsdName, IPAddress ipAddress, Message message)
        {
            NSDName = nsdName;
            IpAddress = ipAddress;
            Message = message;
        }
    }
}
