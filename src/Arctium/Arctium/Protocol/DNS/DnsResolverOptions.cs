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
        public DnsCacheShareMode CacheShareMode { get; private set; }
        public IDnsResolverCache Cache { get; private set; }

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
        /// <param name="useCache">Indicates if resolver should use cache or not. If not then resolver will always make connection to remove dns server</param>
        /// <param name="cacheShareMode"></param>
        /// <param name="cache"></param>
        /// <param name="dnsServers">This servers will be asked first</param>
        public DnsResolverOptions(
            bool useCache = true,
            DnsCacheShareMode cacheShareMode = DnsCacheShareMode.SingleOSProcess,
            IDnsResolverCache cache = null,
            IPAddress[] dnsServers = null,
            int maxResponseTTL = DnsConsts.DefaultMaxResponseTTLSeconds)
        {
            UseCache = useCache;
            CacheShareMode = cacheShareMode;
            Cache = cache;
            DnsServers = dnsServers;
        }

        public static DnsResolverOptions CreateDefault()
        {
            DnsResolverOptions options = new DnsResolverOptions();

            // if (options.Cache == null && options.UseCache) throw new InvalidOperationException("usecache = true, cache = null");

            return options;
        }
    }
}
