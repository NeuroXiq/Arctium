using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS.Server
{
    public class DnsRequestContext
    {
        public Message ClientMessage { get; set; }
        public Message ServerMessage { get; set; }

        public DnsRequestContext(Message clientMessage)
        {
            ClientMessage = clientMessage;
        }
    }
}
