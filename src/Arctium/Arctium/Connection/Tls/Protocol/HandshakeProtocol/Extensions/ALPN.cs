namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions
{
    class ALPN : HandshakeExtension
    {
        public string[] ProtocolNameList;

        public ALPN(string[] nameList) : base(HandshakeExtensionType.ApplicationLayerProtocolNegotiation)
        {
            ProtocolNameList = nameList;
        }
    }
}
