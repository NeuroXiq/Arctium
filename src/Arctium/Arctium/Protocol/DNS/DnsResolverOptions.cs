using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS
{
    public class DnsResolverOptions
    {
        public const int DefaultUdpSocketTimeoutMs = 10000;
        public const int DefaultTcpSocketTimeoutMs = 10000;

        public ResourceRecord[] SBeltServers { get; private set; }

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
        public readonly bool RecursionDesired;

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

        public static DnsResolverOptions CreateDefault(IDnsResolverCache cache = null, ResourceRecord[] sbeltServers = null)
        {
            DnsResolverOptions options = new DnsResolverOptions(
                sbeltServers ?? CreateDefaultSBeltServers(),
                cache ?? new InMemoryDnsResolverCache());

            return options;
        }

        public static ResourceRecord[] CreateDefaultSBeltServers()
        {
            var roots = DnsRootServers.All.SelectMany(t => new ResourceRecord[]
            {
                new ResourceRecord() { Class = QClass.IN, Type = QType.NS, Name = "", TTL = 1000, RData = new RDataNS(t.HostName) },
                new ResourceRecord() { Class = QClass.IN, Type = QType.A, Name = t.HostName, TTL = 1000, RData = new RDataA(t.IPv4Address.ToString()) },
                new ResourceRecord() { Class = QClass.IN, Type = QType.AAAA, Name = t.HostName, TTL = 1000, RData = new RDataAAAA(t.IPv6Address.GetAddressBytes()) },
            }).ToList();

            roots.Add(new ResourceRecord() { Class = QClass.IN, Name = "", Type = QType.NS, RData = new RDataNS("dns.google"), TTL = 1000 });
            roots.Add(new ResourceRecord() { Class = QClass.IN, Name = "dns.google", Type = QType.A, RData = new RDataA("8.8.8.8"), TTL = 1000 });
            roots.Add(new ResourceRecord() { Class = QClass.IN, Name = "", Type = QType.NS, RData = new RDataNS("dns.google"), TTL = 1000 });
            roots.Add(new ResourceRecord() { Class = QClass.IN, Name = "dns.google", Type = QType.A, RData = new RDataA("8.8.4.4"), TTL = 1000 });

            var sbeltServers = roots.ToArray();

            return sbeltServers;
        }
    }
}
