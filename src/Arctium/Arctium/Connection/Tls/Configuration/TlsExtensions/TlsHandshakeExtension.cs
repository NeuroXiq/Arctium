using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System;

namespace Arctium.Connection.Tls.Configuration.TlsExtensions
{
    //
    // Hides internal representation of the handshake extensions to public usage
    //

    public class TlsHandshakeExtension
    {
        public enum ConnectionEnd
        {
            Client = 0,
            Server = 1
        }

        HandshakeExtensionType internalExtensionType;

        public ConnectionEnd ConnectionEndType;

        protected TlsHandshakeExtension(HandshakeExtensionType msgType, ConnectionEnd connectionType)
        {
            internalExtensionType = msgType;
            ConnectionEndType = connectionType;
        }
    }
}
