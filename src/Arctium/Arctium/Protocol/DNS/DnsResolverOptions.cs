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
        public IDndResolverLocalData LocalData { get; private set; }

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
        /// <param name="cacheShareMode"></param>
        /// <param name="cache"></param>
        /// <param name="dnsServers">This servers will be asked first</param>
        public DnsResolverOptions(
            IDndResolverLocalData localData = null,
            IPAddress[] dnsServers = null,
            IPAddress[] sbeltDnsServers = null,
            int maxResponseTTL = DnsConsts.DefaultMaxResponseTTLSeconds)
        {
            LocalData = localData;
            DnsServers = dnsServers;
        }

        public static DnsResolverOptions CreateDefault()
        {
            IDndResolverLocalData localData = new InMemoryDndResolverLocalData();
            DnsResolverOptions options = new DnsResolverOptions(localData);

            // if (options.Cache == null && options.UseCache) throw new InvalidOperationException("usecache = true, cache = null");

            return options;
        }
    }
}
