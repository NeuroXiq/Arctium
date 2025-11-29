using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS
{
    public class DnsResolverOptions
    {
        public bool UseCache { get; private set; }
        public IDnsResolverCache Cache { get; private set; }
        public IPAddress[] SBeltDnsServers { get; private set; }

        /// <summary>
        /// Max TTL. If TTL from received packet exceed this limit it is dropped.
        /// Value in seconds. Default to one week <see cref="DnsConsts.DefaultMaxResponseTTLSeconds"/>
        /// </summary>
        public int MaxResponseTTL { get; private set; }

        /// <summary>
        /// Dns servers to as first
        /// </summary>
        public IPAddress[] DnsServers { get; private set; }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="useCache">Indicates if resolver should use cache or not. If not then resolver will always make connection to remote dns server</param>
        /// <param name="cacheShareMode"></param>
        /// <param name="cache"></param>
        /// <param name="dnsServers">This servers will be asked first</param>
        /// <param name="sbeltDnsServers">Security bet DNS servers. If null then by default root name servers will be used</param>
        public DnsResolverOptions(
            bool useCache = true,
            IDnsResolverCache cache = null,
            IPAddress[] dnsServers = null,
            IPAddress[] sbeltDnsServers = null,
            int maxResponseTTL = DnsConsts.DefaultMaxResponseTTLSeconds)
        {
            UseCache = useCache;
            Cache = cache;
            DnsServers = dnsServers;
            SBeltDnsServers = DnsRootServers.All.Select(t => t.IPv4Address).ToArray();
        }

        public static DnsResolverOptions CreateDefault()
        {
            DnsResolverOptions options = new DnsResolverOptions();

            // if (options.Cache == null && options.UseCache) throw new InvalidOperationException("usecache = true, cache = null");

            return options;
        }
    }
}
