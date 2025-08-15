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
    }
}
