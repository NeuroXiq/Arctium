using Arctium.Connection.Tls.Exceptions;
using Arctium.Connection.Tls.Protocol.AlertProtocol;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System;

namespace Arctium.Connection.Tls.Configuration.TlsExtensions
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
