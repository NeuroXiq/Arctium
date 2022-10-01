using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System;

namespace Arctium.Standards.Connection.Tls.Tls12.Configuration.TlsExtensions
{
     
    public abstract class TlsHandshakeExtension
    {
        public enum ExtensionType
        {
            ALPN,
            SNI
        }

        internal HandshakeExtensionType internalExtensionType;
        public ExtensionType Type { get; private set; }

        protected TlsHandshakeExtension(HandshakeExtensionType msgType)
        {
            if (msgType == HandshakeExtensionType.ApplicationLayerProtocolNegotiation)
                Type = ExtensionType.ALPN;
            else if (msgType == HandshakeExtensionType.ServerName)
                Type = ExtensionType.SNI;
            else throw new Exception("internal");

            internalExtensionType = msgType;
        }
    }
}
