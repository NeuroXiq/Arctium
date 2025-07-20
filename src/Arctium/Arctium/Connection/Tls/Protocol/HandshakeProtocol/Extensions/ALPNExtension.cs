namespace Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol.Extensions
{
    class ALPNExtension : HandshakeExtension
    {
        public string[] ProtocolNameList;

        public ALPNExtension(string[] nameList) : base(HandshakeExtensionType.ApplicationLayerProtocolNegotiation)
        {
            ProtocolNameList = nameList;
        }
    }
}
