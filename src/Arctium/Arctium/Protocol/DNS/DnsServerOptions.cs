using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS
{
    public class DnsServerOptions
    {
        public IDnsServerDataSource DnsServerDataSource { get; set; }
        public int SocketBindPort { get; set; }

        public DnsServerOptions(IDnsServerDataSource dnsServerDataSource)
        {
            DnsServerDataSource = dnsServerDataSource;
            SocketBindPort = DnsConsts.DefaultServerUdpPort;
        }
    }
}
