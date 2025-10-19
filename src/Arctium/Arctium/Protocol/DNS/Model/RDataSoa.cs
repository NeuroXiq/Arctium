using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS.Model
{
    /// <summary>
    /// </summary>
    public class RDataSOA
    {
        /// <summary>
        /// domain-name of the name server that was the original
        /// or primary source of data for this zone
        /// </summary>
        public string MName;

        /// <summary>
        /// a domain-name which specifies the mailbox of the
        /// person responsible for this zone
        /// </summary>
        public string RName;

        /// <summary>
        /// the unsigned 32 bit version number of the original copy
        /// of the zone. zone transfers preserve this value.
        /// this value wraps and should be compared using
        /// sequence space arithmetic
        /// </summary>
        public uint Serial;

        /// <summary>
        /// a 32 bit time interval before the zone should be refreshed
        /// </summary>
        public int Refresh;

        /// <summary>
        /// a 32 bit time interval that shouldelapse before a failed refresh should be retried
        /// </summary>
        public int Retry;

        /// <summary>
        /// a 32 bit time value that specifies the upper limit on
        /// the time interval that can elapse before
        /// the zone is no longer authoritative
        /// </summary>
        public int Expire;

        /// <summary>
        /// The unsigned 32 bit minimum ttl field that should be exported with any rr from this zonne
        /// </summary>
        public uint Minimum;
    }
}
