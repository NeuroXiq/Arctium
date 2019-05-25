using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System;

namespace Arctium.Connection.Tls.Configuration.TlsExtensions
{
    //
    // Encapsulates internal representation of the handshake extensions to public usage.
    // Not all extensions should be defined for public usage, e.g. padding extension
    // and thats why only several can be configurable by the user
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
