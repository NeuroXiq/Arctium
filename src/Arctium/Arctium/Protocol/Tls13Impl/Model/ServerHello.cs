using Arctium.Protocol.Tls13Impl.Model.Extensions;
using System.Collections.Generic;

namespace Arctium.Protocol.Tls13Impl.Model
{
    class ServerHello
    {
        public static readonly byte[] RandomSpecialConstHelloRetryRequest = new byte[]
        {
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
        };

        public const ushort LegacyVersion = 0x0303;
        public const byte LegacyCompressionMethod = 0;
        public byte[] Random { get; set; }
        public byte[] LegacySessionIdEcho { get; private set; }
        public CipherSuite CipherSuite { get; private set; }
        public List<Extension> Extensions { get; private set; }

        public ServerHello(byte[] random, byte[] legacySessionIdEcho, CipherSuite cipherSuite, List<Extension> extensions)
        {
            Random = random;
            LegacySessionIdEcho = legacySessionIdEcho;
            CipherSuite = cipherSuite;
            Extensions = extensions;
        }
    }
}
