using Arctium.Connection.Tls.Configuration;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Connection.Tls
{
    public class TlsConnectionResult
    {
        public HandshakeExtension[] ExtensionsResult;
        public Tls12Session Session;
        public TlsStream TlsStream;
    }
}
