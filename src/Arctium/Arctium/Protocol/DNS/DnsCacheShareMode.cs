using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS
{
    /// <summary>
    /// Cache mode for <see cref="DnsResolver"/>
    /// </summary>
    public enum DnsCacheShareMode
    {
        /// <summary>
        /// Separate cachew will be created for each instance of <see cref="DnsResolver"/> class created
        /// </summary>
        ClassInstance = 1,

        /// <summary>
        /// Cache will be shared among all <see cref="DnsResolver"/> instances created in single OS Process
        /// </summary>
        SingleOSProcess = 2,

        /// <summary>
        /// Cache will be shared among all <see cref="DnsResolver"/> instances created in all OS processes currently running on the machine.
        /// </summary>
        AllOSProcesses = 3
    }
}
