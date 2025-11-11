using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS.Model
{
    public class RDataMB
    {
        /// <summary>
        /// a domain-name which specifies as host which has the specified mailbox
        /// </summary>
        public string MADName;

        public RDataMB() { }
        public RDataMB(string madName) { MADName = madName; }
    }
}
