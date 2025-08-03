using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS
{
    public class DnsResolverOptions
    {
        public bool UseCache { get; private set; }
        public DnsCacheShareMode CacheShareMode { get; private set; }

        public DnsResolverOptions(
            bool useCache = true,
            DnsCacheShareMode cacheShareMode = DnsCacheShareMode.SingleOSProcess)
        {
            UseCache = useCache;
            CacheShareMode = cacheShareMode;
        }

        public static DnsResolverOptions CreateDefault()
        {
            DnsResolverOptions options = new DnsResolverOptions();

            return options;
        }
    }
}
