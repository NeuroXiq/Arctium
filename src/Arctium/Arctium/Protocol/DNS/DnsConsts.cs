using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS
{
    public static class DnsConsts
    {
        /// <summary>
        /// rfc-1035 default 1 week in seconds
        /// </summary>
        public const int DefaultMaxResponseTTLSeconds = 604800;

        /// <summary>
        /// rfc-1035 page 8
        /// </summary>
        public const int MaxLabelLength = 63;

        /// <summary>
        /// rfc-1035 page 10 , label octets and label length octets
        /// </summary>
        public const int MaxDomainNameLength = 255;

        /// <summary>
        /// characted-string max length (length byte not included)
        /// </summary>
        public const int MaxCharacterStringLength = 255;

        /// <summary>
        /// page 10 rfc-1035
        /// </summary>
        public const int UdpSizeLimit = 512;

        public const int DefaultServerDnsPort = 53;
    }
}
