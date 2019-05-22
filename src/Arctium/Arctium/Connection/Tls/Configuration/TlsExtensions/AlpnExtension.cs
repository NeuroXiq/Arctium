using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Connection.Tls.Configuration.TlsExtensions
{
    class AlpnExtension : TlsHandshakeExtension
    {
        public AlpnExtension() : base(HandshakeExtensionType.ALPN) { }
    }
}
