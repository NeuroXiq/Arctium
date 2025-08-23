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
        public const int TotalLengthOfDomainName = 255;

        /// <summary>
        /// page 10 rfc-1035
        /// </summary>
        public const int UDPSizeLimit = 512;

        public const int DefaultServerUdpPort = 53;
    }
}
