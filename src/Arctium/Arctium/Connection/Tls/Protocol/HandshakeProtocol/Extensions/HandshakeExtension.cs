namespace Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol.Extensions
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
