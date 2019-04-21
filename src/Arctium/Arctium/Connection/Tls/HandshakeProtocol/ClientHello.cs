using Arctium.Connection.Tls.Protocol;
using Arctium.Connection.Tls.RecordProtocol;

namespace Arctium.Connection.Tls.HandshakeProtocol
{
    class ClientHello
    {
        public ProtocolVersion ClientVersion;
        public HelloRandom Random;
        public SessionID SessionID;
        CipherSuite[] CipherSuites;
        CompressionMethod[] CompressionMethods;

    }
}
