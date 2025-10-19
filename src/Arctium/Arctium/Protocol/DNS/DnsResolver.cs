using Arctium.Protocol.DNS.Protocol;
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
        private DnsResolverImpl dnsResolverImpl;

        public DnsResolver() : this (DnsResolverOptions.CreateDefault()) { }

        public DnsResolver(DnsResolverOptions options)
        {
            this.options = options;
            dnsResolverImpl = new DnsResolverImpl(options);
        }

        public IPAddress ResolveHostNameToHostAddress(string hostName)
        {
            dnsResolverImpl.ResolveHostNameToHostAddress(hostName);

            return null;
        }

        public string ResolveHostAddressToHostName(IPAddress ipAddress)
        {
            dnsResolverImpl.ResolveHostAddressToHostName(ipAddress);

            return null;
        }

        public object ResolveGeneralLookupFunction()
        {
            dnsResolverImpl.ResolveGeneralLookupFunction();

            return null;
        }
    }
}
