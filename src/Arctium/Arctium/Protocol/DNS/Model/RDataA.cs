using Arctium.Protocol.DNS.Protocol;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS.Model
{
    /// <summary>
    /// </summary>
    public class RDataA
    {
        public uint Address;

        public RDataA() { }

        public RDataA(uint address)
        {
            Address = address;
        }

        public RDataA(string address)
        {
            Address = DnsSerialize.Ipv4ToUInt(address);
        }
    }
}
