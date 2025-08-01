using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions.Enum;

namespace Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions
{
    public class HandshakeExtension
    {
        public HandshakeExtensionType Type;

        public HandshakeExtension(HandshakeExtensionType type)
        {
            this.Type = type;
        }
    }
}
