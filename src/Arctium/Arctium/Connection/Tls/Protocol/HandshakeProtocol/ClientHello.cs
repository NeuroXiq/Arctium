using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.Protocol.RecordProtocol;

namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol
{
    class ClientHello : Handshake
    {
        public ProtocolVersion ClientVersion;
        public HelloRandom Random;
        public SessionID SessionID;
        public CipherSuite[] CipherSuites;
        public CompressionMethod[] CompressionMethods;

    }
}
