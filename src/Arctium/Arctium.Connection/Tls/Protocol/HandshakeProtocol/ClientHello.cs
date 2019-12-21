using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol
{
    class ClientHello : Handshake
    {
        public ProtocolVersion ClientVersion;
        //public HelloRandom Random;
        public byte[] Random;
        //public SessionID SessionID;
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
