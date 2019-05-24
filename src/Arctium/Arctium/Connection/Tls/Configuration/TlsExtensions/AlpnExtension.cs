using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Connection.Tls.Configuration.TlsExtensions
{
    public class AlpnExtension : TlsHandshakeExtension
    {
        string requestProtocols;
        string responseProtocol;

        public AlpnExtension() : base(HandshakeExtensionType.ApplicationLayerProtocolNegotiation) { }


        
    }
}
