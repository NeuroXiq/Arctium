using Arctium.Connection.Tls.Tls13.Model.Extensions;

namespace Arctium.Connection.Tls.Tls13.Model
{
    class ServerHello
    {
        public const ushort LegacyVersion = 0x0303;
        public const byte LegacyCompressionMethod = 0;
        public byte[] Random { get; private set; }
        public byte[] LegacySessionIdEcho { get; private set; }
        public CipherSuite CipherSuite { get; private set; }
        public Extension[] Extensions { get; private set; }

        public ServerHello(byte[] random, byte[] legacySessionIdEcho, CipherSuite cipherSuite, Extension[] extensions)
        {
            Random = random;
            LegacySessionIdEcho = legacySessionIdEcho;
            CipherSuite = cipherSuite;
            Extensions = extensions;
        }   
    }
}
