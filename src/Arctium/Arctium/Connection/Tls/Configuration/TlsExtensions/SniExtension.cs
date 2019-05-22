using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Connection.Tls.Configuration.TlsExtensions
{
    public class SniExtension : TlsHandshakeExtension
    {
        public SniExtension() : base(HandshakeExtensionType.ServerName)
        {

        }
    }
}
