using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS.Model
{
    /// <summary>
    ///  CNAME RRs cause no additional section processing, but name servers may
    /// choose to restart the query at the canonical name in certain cases.See
    ///
    /// the description of name server logic in [RFC - 1034] for details
    /// </summary>
    public class RDataCNAME
    {
        /// <summary>
        ///  A <domain-name> which specifies the canonical or primary
        /// name for the owner.The owner name is an alias
        /// </summary>
        public string CName;

        public RDataCNAME() { }
        public RDataCNAME(string cname) { CName = cname; }
    }
}
