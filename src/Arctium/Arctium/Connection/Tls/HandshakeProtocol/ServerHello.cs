using Arctium.Connection.Tls.Protocol;

namespace Arctium.Connection.Tls.HandshakeProtocol
{
    class ServerHello
    {
        public ProtocolVersion ProtocolVersion;
        public HelloRandom Random;
        CipherSuite CipherSuite;
        CompressionMethod CompressionMethod;
    }
}
