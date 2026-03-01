using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS
{
    public class DnsResolverOptions
    {
        public const int DefaultUdpSocketTimeoutMs = 10000;
        public const int DefaultTcpSocketTimeoutMs = 10000;

        public ResourceRecord[] SBeltServers { get; set; }
        
        public IDnsResolverCache Cache { get; private set; }

        /// <summary>
        /// Max TTL. If TTL from received packet exceed this limit it is dropped.
        /// Value in seconds. Default to one week <see cref="DnsConsts.DefaultMaxResponseTTLSeconds"/>
        /// </summary>
        public int MaxResponseTTL { get; private set; }

        /// <summary>
        /// Maximum number of requests (sum of udp and tcp) that resolver can do.
        /// If resolver is not able to complete in less that this limit
        /// exception will be thrown
        /// </summary>
        public int MaxRequestCountForResolve { get; private set; }
        
        public int UdpSocketRecvTimeoutMs { get; private set; }
        
        public int TcpSocketRecvTimeoutMs { get; private set; }
        
        /// <summary>
        /// Recursion-desired flag
        /// </summary>
        public bool RecursionDesired { get; set; }

        /// <summary>
        /// </summary>
        public DnsResolverOptions(
            ResourceRecord[] sbeltDnsServers,
            IDnsResolverCache cache,
            int maxResponseTTL = DnsConsts.DefaultMaxResponseTTLSeconds,
            int maxRequestCountForResolve = 150,
            int udpSocketTimeout = DefaultUdpSocketTimeoutMs,
            int tcpSocketTimeout = DefaultTcpSocketTimeoutMs,
            bool recursionDesired = true)
        {
            if (sbeltDnsServers == null || sbeltDnsServers.Length == 0)
                throw new ArgumentException("sbeltDnsServers is null or empty");

            if (cache == null)
                throw new ArgumentNullException("cache");

            MaxRequestCountForResolve = maxRequestCountForResolve;
            UdpSocketRecvTimeoutMs = udpSocketTimeout;
            TcpSocketRecvTimeoutMs = tcpSocketTimeout;
            SBeltServers = sbeltDnsServers;
            Cache = cache;
            RecursionDesired = recursionDesired;
        }

        public static DnsResolverOptions CreateDefault()
        {
            return new DnsResolverOptions(CreateDefaultSBeltServers(), CreateDefaultCache());
        }

        public static IDnsResolverCache CreateDefaultCache()
        {
            return new InMemoryDnsResolverCache();
        }
        
        // public static void 

        public static ResourceRecord[] CreateDefaultSBeltServers()
        {
            var sbeltServers = DnsWellKnownServers.GetAllAsRecords();

            return sbeltServers;
        }
    }
}
