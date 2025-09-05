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

        public int PortUdp { get; set; }
        public int PortTcp { get; set; }
        public CancellationToken CancellationToken { get; set; }

        public DnsServerOptions(IDnsServerDataSource dnsServerDataSource)
        {
            DnsServerDataSource = dnsServerDataSource;
            PortUdp = DnsConsts.DefaultServerUdpPort;
        }

        public static DnsServerOptions CreateDefault(IDnsServerDataSource dataSource, CancellationToken cancellationToken)
        {
            return new DnsServerOptions(dataSource)
            {
                CancellationToken = cancellationToken,
                PortTcp = 53,
                PortUdp = 53
            };
        }
    }
}
