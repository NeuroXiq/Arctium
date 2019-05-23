namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions
{
    class ALPN : HandshakeExtension
    {
        public string[] ProtocolNameList;

        public ALPN() { base.Type = HandshakeExtensionType.ApplicationLayerProtocolNegotiation; }
    }
}
