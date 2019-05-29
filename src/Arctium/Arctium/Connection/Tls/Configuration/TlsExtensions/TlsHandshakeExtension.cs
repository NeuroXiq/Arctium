using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System;

namespace Arctium.Connection.Tls.Configuration.TlsExtensions
{
     
    public abstract class TlsHandshakeExtension
    {
        internal HandshakeExtensionType internalExtensionType;

        protected TlsHandshakeExtension(HandshakeExtensionType msgType)
        {
            internalExtensionType = msgType;
        }
    }
}
