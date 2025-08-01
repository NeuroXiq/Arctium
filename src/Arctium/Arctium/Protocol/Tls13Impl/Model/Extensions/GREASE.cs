using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.Tls13Impl.Model.Extensions
{
    internal static class GREASE
    {
        /// <summary>
        /// cipher suites and Application-Layer Protocol Negotiation (ALPN) [RFC7301] identifiers
        /// </summary>
        public static readonly byte[][] CS_ALPN = new byte[][]
        {
            new byte[] { 0x0A,0x0A },
            new byte[] { 0x1A,0x1A },
            new byte[] { 0x2A,0x2A },
            new byte[] { 0x3A,0x3A },
            new byte[] { 0x4A,0x4A },
            new byte[] { 0x5A,0x5A },
            new byte[] { 0x6A,0x6A },
            new byte[] { 0x7A,0x7A },
            new byte[] { 0x8A,0x8A },
            new byte[] { 0x9A,0x9A },
            new byte[] { 0xAA,0xAA },
            new byte[] { 0xBA,0xBA },
            new byte[] { 0xCA,0xCA },
            new byte[] { 0xDA,0xDA },
            new byte[] { 0xEA,0xEA },
            new byte[] { 0xFA,0xFA },
        };


        /// <summary>
        /// extensions, named groups, signature algorithms, and versions
        /// </summary>
        public static readonly ushort[] EX_NG_SA_VER = new ushort[]
        {
            0x0A0A,
            0x1A1A,
            0x2A2A,
            0x3A3A,
            0x4A4A,
            0x5A5A,
            0x6A6A,
            0x7A7A,
            0x8A8A,
            0x9A9A,
            0xAAAA,
            0xBABA,
            0xCACA,
            0xDADA,
            0xEAEA,
            0xFAFA,
        };

        /// <summary>
        /// PskKeyExchangeModes
        /// </summary>
        public static readonly ushort[] PSK_KE_MODES = new ushort[]
        {
            0x0B,
            0x2A,
            0x49,
            0x68,
            0x87,
            0xA6,
            0xC5,
            0xE4,
        };
    }
}
