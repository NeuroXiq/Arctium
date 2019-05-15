using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.Protocol.RecordProtocol;

namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol
{
    class ServerHello : Handshake
    {

        public ServerHello()
        {
            MsgType = HandshakeType.ServerHello;
        }

        public ProtocolVersion ProtocolVersion;
        public byte[] Random;
        //public SessionID SessionID;
        public byte[] SessionID;
        public CipherSuite CipherSuite;
        public CompressionMethod CompressionMethod;
    }
}
