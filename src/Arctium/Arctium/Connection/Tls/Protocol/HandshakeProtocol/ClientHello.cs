using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol
{
    class ClientHello : Handshake
    {
        public ProtocolVersion ClientVersion;
        public byte[] Random;
        public byte[] SessionID;
        public CipherSuite[] CipherSuites;
        public CompressionMethod[] CompressionMethods;

        public HandshakeExtension[] Extensions;

        public ClientHello()
        {
            base.MsgType = HandshakeType.ClientHello;
        }
    }
}
