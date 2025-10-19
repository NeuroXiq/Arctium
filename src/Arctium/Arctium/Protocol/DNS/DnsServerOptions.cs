using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS
{
    public class DnsServerOptions
    {
        public IDnsServerRecordsData DnsServerDataSource { get; private set; }
        public IDnsServerRecordsData DnsServerCacheDataSource { get; private set; }

        public int PortUdp { get; private set; }
        public int PortTcp { get; private set; }
        public CancellationToken CancellationToken { get; private set; }
        public bool RecursionAvailable { get; private set; }

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
                PortUdp = 53,
                DnsServerCacheDataSource = null
            };
        }

        public void EnableRecursionAvailable(IDnsServerRecursionService recursionService)
        {
            RecursionAvailable = true;
            RecursionService = recursionService;
        }

        public void SetCache(IDnsServerRecordsData dnsServerCacheDataSource)
        {
            DnsServerCacheDataSource = dnsServerCacheDataSource;
        }
    }
}
