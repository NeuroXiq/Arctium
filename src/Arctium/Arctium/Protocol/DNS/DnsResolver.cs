using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS
{
    public class DnsResolver
    {
        private DnsResolverOptions options;

        public DnsResolver() : this (DnsResolverOptions.CreateDefault()) { }

        public DnsResolver(DnsResolverOptions options)
        {
            this.options = options;
        }

        public IPAddress HostNameToHostAddress(string hostName)
        {
            return null;
        }

        public string HostAddressToHostName(IPAddress ipAddress)
        {
            return null;
        }


    }
}
