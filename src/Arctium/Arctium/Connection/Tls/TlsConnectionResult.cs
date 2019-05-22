using Arctium.Connection.Tls.Configuration;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Connection.Tls
{
    public class TlsConnectionResult
    {
        ///<summary>Indicates on which version of TLS connection was established.</summary>
        public TlsProtocolType ProtocolType;
        public HandshakeExtension[] Extensions;
        public TlsStream TlsStream;
    }
}
