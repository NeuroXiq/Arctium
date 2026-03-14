using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS.Server
{
    public class DnsServerOptions
    {
        public IDnsServerRecordsData DnsServerDataSource { get; private set; }
        public IDnsServerRecordsData DnsServerCacheDataSource { get; private set; }
        public IDnsServerMessageIO MessageIO { get; set; }
        public bool RecursionAvailable { get; private set; }
        public IDnsServerRecursionService RecursionService { get; set; }
        public CancellationTokenSource StopServerCancellationTokenSource { get; set; }

        public DnsServerOptions(IDnsServerRecordsData dnsServerDataSource)
        {
            DnsServerDataSource = dnsServerDataSource;
        }

        public static DnsServerOptions CreateDefault(IDnsServerRecordsData dataSource)
        {
            DnsServerOptions options = new DnsServerOptions(dataSource)
            {
                StopServerCancellationTokenSource = new CancellationTokenSource(),
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

        public void AddMessageIO_ClassicTcp(
            int port = DnsConsts.DefaultServerDnsPort,
            int receiveTimeoutMs = DnsConsts.ArctiumDefaultTcpReceiveTimeoutMs,
            int listenBacklog = DnsConsts.ArctiumDefaultTcpListenBacklog)
        {
            MessageIO.AddAdapter(new DnsServerMessageIO_TcpClassic(port, receiveTimeoutMs, listenBacklog));
        }

        public void AddMessageIO_ClassicUdp(int port = DnsConsts.DefaultServerDnsPort)
        {
            MessageIO.AddAdapter(new DnsServerMessageIO_UdpClassic(port));
        }

        public void AddMessageIO_Custom()
        {
            
        }

        /// <summary>
        /// Consider override kestrel configuration by inheriting from <see cref="DnsServerMessageIO_DoHRfc8484"/>
        /// </summary>
        /// <param name="appUrl">e.g. "https://www.localhost.com"</param>
        /// <param name="getPath">e.g. "/dns-get-path"</param>
        /// <param name="getPathQueryParamName">e.g. 'dns' to match example: "www.dns-doh.com/dns-get-path?dns=...."</param>
        /// <param name="postPath"></param>
        /// <param name="certificate"></param>
        /// <exception cref="NotImplementedException"></exception>
        public void AddMessageIO_DoH(
            string appUrl,
            string getPath,
            string postPath,
            X509Certificate2 certificate)
        {
            MessageIO.AddAdapter(new DnsServerMessageIO_DoHRfc8484(appUrl, getPath, postPath, certificate));
        }
    }
}
