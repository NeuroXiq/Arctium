using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Connection.Tls.Configuration.TlsExtensions
{
    class SniExtension : TlsHandshakeExtension
    {
        public SniExtension() : base(HandshakeExtensionType.ServerName)
        {

        }
    }
}
