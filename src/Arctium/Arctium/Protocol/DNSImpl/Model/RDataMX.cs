using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNSImpl.Model
{
    /// <summary>
    /// MX Records cause type A additional section processing for the host
    /// specified by EXCHANGE. The use of mx rr is explained in detail in [rfc-974]
    /// </summary>
    struct RDataMX
    {
        /// <summary>
        /// a 16 bit integer which specifies the preferences give to this rr among other at the same owner.
        /// lower values are preferred.
        /// </summary>
        public ushort Preference;

        /// <summary>
        /// a domain-name which specifies a host willing to act as a mail
        /// exchange for the owner name
        /// </summary>
        public string Exchange;
    }
}
