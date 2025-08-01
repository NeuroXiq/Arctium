namespace Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions
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
