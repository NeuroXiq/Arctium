using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS.Server
{
    public class DnsServerOptions
    {
        public IDnsServerRecordsData DnsServerDataSource { get; private set; }
        public IDnsServerRecordsData DnsServerCacheDataSource { get; private set; }
        public IDnsServerMessageIO MessageIO { get; set; }

        public int PortUdp { get; private set; }
        public int PortTcp { get; private set; }
        public CancellationToken CancellationToken { get; private set; }
        public bool RecursionAvailable { get; private set; }
        public IDnsServerRecursionService RecursionService { get; set; }
        public CancellationTokenSource StopServerCancellationTokenSource { get; set; }

        public DnsServerOptions(IDnsServerRecordsData dnsServerDataSource)
        {
            DnsServerDataSource = dnsServerDataSource;
            PortUdp = DnsConsts.DefaultServerDnsPort;
        }

        public static DnsServerOptions CreateDefault(IDnsServerRecordsData dataSource)
        {
            return new DnsServerOptions(dataSource)
            {
                StopServerCancellationTokenSource = new CancellationTokenSource(),
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

        public void AddMessageIO_Classic()
        {

        }

        public void AddMessageIO_DoH()
        {
            
        }

        public void AddMessageIO_Custom()
        {
            
        }
    }
}
