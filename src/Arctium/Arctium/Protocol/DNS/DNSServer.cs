using Arctium.Protocol.DNSImpl.Protocol;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS
{
    public class DnsServer
    {
        DnsServerImpl dnsServerImpl;

        public DnsServer(DnsServerOptions options)
        {
            dnsServerImpl = new DnsServerImpl(options);
        }

        public void StartUdp() => dnsServerImpl.StartUdp();
        public void StartTcp() => dnsServerImpl.StartTcp();
    }
}
