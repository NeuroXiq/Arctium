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

        internal override HandshakeExtension GetResponse(HandshakeExtension extensionFromClient)
        {
            ALPNExtension clientRequest = (ALPNExtension)extensionFromClient;

            //select protocol which both parties share
            // 'this' instance is created on server side and that means that 'SupportedProcolName'
            // contains data on server side.

            string[] clientProtocols = ((ALPNExtension)extensionFromClient).ProtocolNameList;
            string[] serverProtocols = SupportedProtocolNames;

            foreach (string serverProt in serverProtocols)
            {
                foreach (string clientProt in clientProtocols)
                {
                    if (serverProt == clientProt)
                        return new ALPNExtension(new string[] { serverProt });
                }
            }

            // not found, not sure what to do
            // throw exception now or somewhere else (?)

            throw new FatalAlertException(
                "AlpnExtension",
                "On finding supported protocol name by both parties on SERVER SIDE", 
                (int)AlertDescription.NoApplicationProtocol,
                "not found protocol name which support both parties of the connection. All client protocll names do not match supported server protocol names");
        }
    }
}
