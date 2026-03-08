using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
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
            DnsServerOptions options = new DnsServerOptions(dataSource)
            {
                StopServerCancellationTokenSource = new CancellationTokenSource(),
                PortTcp = 53,
                PortUdp = 53,
                DnsServerCacheDataSource = null,
                MessageIO = new DnsServerMessageIO()
            };

            options.AddMessageIO_ClassicUdp();
            options.AddMessageIO_ClassicTcp();

            return options;
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

        public void AddMessageIO_ClassicTcp(int port = DnsConsts.DefaultServerDnsPort)
        {
            
        }

        public void AddMessageIO_ClassicUdp(int port = DnsConsts.DefaultServerDnsPort)
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
