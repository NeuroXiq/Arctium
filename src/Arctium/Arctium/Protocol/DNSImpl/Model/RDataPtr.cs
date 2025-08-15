using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNSImpl.Model
{
    /// <summary>
    /// ptr records cause no additional section processing. these
    /// rrs are used in special domains to point to some other
    /// location in the domain space
    /// </summary>
    public class RDataPtr
    {
        /// <summary>
        /// a domain-name which points to some
        /// location in the domain name space
        /// </summary>
        public string PtrDName;
    }
}
