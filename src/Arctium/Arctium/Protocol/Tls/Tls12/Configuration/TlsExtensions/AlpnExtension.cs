using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions;
using Arctium.Protocol.Tls.Tls12.Configuration.TlsExtensions;

namespace Arctium.Protocol.Tls.Configuration.TlsExtensions
{
    public class AlpnExtension : TlsHandshakeExtension
    {
        public string[] SupportedProtocolNames { get; private set; }
        public string SelectedProtocolName { get; private set; }
       
        public AlpnExtension(string[] supportedProtocolNames) : base(HandshakeExtensionType.ApplicationLayerProtocolNegotiation)
        {
            SupportedProtocolNames = supportedProtocolNames;
        }

        public AlpnExtension(string responsedProtocolName) : base(HandshakeExtensionType.ApplicationLayerProtocolNegotiation)
        {
            SelectedProtocolName = responsedProtocolName;
        }

        
    }
}
