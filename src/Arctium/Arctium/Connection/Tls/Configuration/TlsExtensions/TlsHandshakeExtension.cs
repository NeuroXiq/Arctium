using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System;

namespace Arctium.Connection.Tls.Configuration.TlsExtensions
{
    //
    // Encapsulates internal representation of the handshake extensions to public usage.
    // Not all extensions should be defined for public usage, e.g. padding extension
    // and thats why only several can be configurable by the user
    //

    public abstract class TlsHandshakeExtension
    {
        internal HandshakeExtensionType internalExtensionType;

        protected TlsHandshakeExtension(HandshakeExtensionType msgType)
        {
            internalExtensionType = msgType;
        }


        internal abstract HandshakeExtension GetResponse(HandshakeExtension extensionFromClient);

        internal abstract HandshakeExtension ConvertToClientRequest();

    }
}
