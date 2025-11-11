using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS.Model
{
    public class RDataMR
    {
        /// <summary>
        /// a domain-name which specifies a mailbox which is the
        /// propert rename of the specified mailbox
        /// </summary>
        public string NewName;

        public RDataMR() { }
        public RDataMR(string newName) { NewName = newName; }
    }
}
