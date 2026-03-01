using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS
{
    public abstract class DnsClientMessageIO
    {
        public abstract Task<Message> QueryServer(Message input);
    }
}
