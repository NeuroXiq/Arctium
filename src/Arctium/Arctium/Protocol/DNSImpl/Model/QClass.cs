using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNSImpl.Model
{
    /// <summary>
    /// CLASS fields appear in resource records
    /// </summary>
    public enum QClass : ushort
    {
        /// <summary>
        /// 1 the Internet
        /// </summary>
        IN = 1,

        /// <summary>
        /// 2the CSNET class (obsolete - used only for examples in some obsolete RFCs)
        /// </summary>
        CS = 2,

        /// <summary>
        /// 3 the CHAOS class
        /// </summary>
        CH = 3,

        /// <summary>
        /// 4 Hesiod
        /// </summary>
        HS = 4,

        /// <summary>
        /// (This can only appear in query) QCLASS fields appear in the question section of a query
        /// </summary>
        AnyClass = 255,
    }
}
