using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNSImpl.Model
{
    /// <summary>
    /// experimental
    /// </summary>
    public class RDataMINFO
    {
        /// <summary>
        /// a domain-name which specifies a mailbox which is responsible
        /// for the mailing list or mailbox.
        /// if this domain names the root, the owner of the minfo rr
        /// is responsible for itself
        /// </summary>
        public string RMailbx;

        /// <summary>
        /// a domain-name which specifies a mailbox which is to receive error messages
        /// related to the mailing list or mailbox specified by the owner of the minfo rr
        /// </summary>
        public string EMailbx;
    }
}
