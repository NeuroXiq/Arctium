using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS
{
    public class DnsRootServer
    {
        public readonly char Letter;
        public readonly IPAddress IPv4Address;
        public readonly IPAddress IPv6Address;
        public readonly string ASNumber;
        public readonly string OldName;
        public readonly string Operator;
        public readonly string OperatorOrigin;
        public readonly string Location;
        public readonly string NoOfSites;
        public readonly string Software;

        public DnsRootServer(
            char letter,
            string ipv4Address,
            string ipv6Address,
            string asNumber,
            string oldName,
            string optor,
            string optorOrigin,
            string location,
            string noOfSites,
            string software
            )
        {
            Letter = letter;
            IPv4Address = IPAddress.Parse(ipv4Address);
            IPv6Address = IPAddress.Parse(ipv6Address);
            ASNumber = asNumber;
            OldName = oldName;
            Operator = optor;
            OperatorOrigin = optorOrigin;
            Location = location;
            NoOfSites = noOfSites;
            Software = software;
        }
    }
}
