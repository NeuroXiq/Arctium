using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS.Model
{
    /// <summary>
    /// obsolete
    /// </summary>
    public class RDataMD
    {
        ///<summary>
        /// A domain-name which specified a host which has a  
        /// mail agent for the domain which sould be able to deliver 
        /// mail for the domain
        /// </summary>
        public string MADName;

        public RDataMD() { }
        public RDataMD(string madName) { MADName = madName; }
    }
}
