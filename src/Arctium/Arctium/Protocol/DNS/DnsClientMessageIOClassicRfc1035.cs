using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS
{
    public class DnsClientMessageIOClassicRfc1035 : DnsClientMessageIO
    {
        public override Task<Message> QueryServer(Message input)
        {
            throw new NotImplementedException();
        }
    }
}
