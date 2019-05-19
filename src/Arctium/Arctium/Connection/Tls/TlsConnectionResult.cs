using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Connection.Tls
{
    public class TlsConnectionResult
    {
        public HandshakeExtension[] Extensions;
        public TlsStream TlsStream;
    }
}
