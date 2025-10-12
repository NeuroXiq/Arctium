using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS
{
    public class DnsServerOptions
    {
        public IDnsServerRecordsData DnsServerDataSource { get; set; }

        public int PortUdp { get; set; }
        public int PortTcp { get; set; }
        public CancellationToken CancellationToken { get; set; }
        public bool RecursionAvailable { get; set; }

        public IDnsServerRecursionService RecursionService { get; set; }

        public DnsServerOptions(IDnsServerRecordsData dnsServerDataSource)
        {
            DnsServerDataSource = dnsServerDataSource;
            PortUdp = DnsConsts.DefaultServerUdpPort;
        }

        public static DnsServerOptions CreateDefault(IDnsServerRecordsData dataSource, CancellationToken cancellationToken)
        {
            return new DnsServerOptions(dataSource)
            {
                CancellationToken = cancellationToken,
                PortTcp = 53,
                PortUdp = 53
            };
        }

        public void EnableRecursionAvailable(IDnsServerRecursionService recursionService)
        {
            RecursionAvailable = true;
            RecursionService = recursionService;
        }
    }
}
