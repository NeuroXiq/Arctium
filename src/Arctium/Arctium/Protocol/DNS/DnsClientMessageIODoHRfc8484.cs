using Arctium.Protocol.DNS.Model;
using System.Net;

namespace Arctium.Protocol.DNS
{
    public class DnsClientMessageIODoHRfc8484 : IDnsClientMessageIO
    {
        public DnsClientMessageIODoHRfc8484()
        {
            
        }

        public Task<Message> QueryServerAsync(Message input, IPAddress serverIpAddress)
        {
            throw new NotImplementedException();
        }
    }
}
