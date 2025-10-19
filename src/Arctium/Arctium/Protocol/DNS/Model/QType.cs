using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS.Model
{
    /// <summary>
    /// Type fields are used in resource records
    /// </summary>
    public enum QType : ushort
    {
        /// <summary>
        /// 1 a host address
        /// </summary>
        A = 1,

        /// <summary>
        /// 2 an authoritative name server
        /// </summary>
        NS = 2,

        /// <summary>
        /// 3 a mail destination (obsolete - use MX)
        /// </summary>
        MD = 3,

        /// <summary>
        /// 4 a mail forwarder (obsolete - use mx)
        /// </summary>
        MF = 4,

        /// <summary>
        /// 5 the canonical name for an alias
        /// </summary>
        CNAME = 5,

        /// <summary>
        /// 6 marks the start of a zone of authority
        /// </summary>
        SOA =  6,

        /// <summary>
        /// 7 a mailbox domain name (experimental)
        /// </summary>
        MB = 7,

        /// <summary>
        /// 8 a mail group member (experimental)
        /// </summary>
        MG = 8,

        /// <summary>
        /// 9 a mail rename domain name (experimental)
        /// </summary>
        MR = 9,

        /// <summary>
        /// 10 a null RR (experimental)
        /// </summary>
        NULL = 10,

        /// <summary>
        /// 11 a well known service description
        /// </summary>
        WKS = 11,

        /// <summary>
        /// 12 a domain name pointer
        /// </summary>
        PTR = 12,

        /// <summary>
        /// 13 host information
        /// </summary>
        HINFO = 13,

        /// <summary>
        /// 14 mailbox or mail list information
        /// </summary>
        MINFO = 14,

        /// <summary>
        /// 15 mail exchange
        /// </summary>
        MX = 15,

        /// <summary>
        /// 16 text strings
        /// </summary>
        TXT = 16,

        /// <summary>
        /// Ipv6
        /// </summary>
        AAAA = 28,

        /// <summary>
        /// 252 a request for a transfer of an entire zone (Only in query)
        /// </summary>
        AXFR = 252,

        /// <summary>
        /// 253 a request for mailbox-related records (mb, mg or mr) (Only in query)
        /// </summary>
        MAILB = 253,

        /// <summary>
        /// 254 a request for mail agent rrs (obsolete - see mx) (Only in query)
        /// </summary>
        MAILA = 254,

        /// <summary>
        /// * - 255 a request for all records (Only in query)
        /// </summary>
        All = 255
    }
}
