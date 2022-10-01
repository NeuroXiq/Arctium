using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol
{
    class ServerHello : Handshake
    {
        public ProtocolVersion ProtocolVersion;
        public byte[] Random;
        //public SessionID SessionID;
        public byte[] SessionID;
        public CipherSuite CipherSuite;
        public CompressionMethod CompressionMethod;
        public HandshakeExtension[] Extensions;

        public ServerHello()
        {
            MsgType = HandshakeType.ServerHello;
        }
    }
}
