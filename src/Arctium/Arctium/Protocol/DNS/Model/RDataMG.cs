using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS.Model
{
    /// <summary>
    /// experimental
    /// </summary>
    public class RDataMG
    {
        /// <summary>
        /// a domain-name which specifies a mailbox which is a 
        /// member of the mail group specified by the domain name
        /// </summary>
        public string MGMName;

        public RDataMG() { }
        public RDataMG(string mgmName ) { MGMName = mgmName; }
    }
}
