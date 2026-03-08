using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS.Resolver
{
    public class DnsResolverOptions
    {
        public ResourceRecord[] SBeltServers { get; set; }
        public IDnsResolverCache Cache { get; set; }
        public IDnsResolverMessageIO ClientMessageIO { get; set; }

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
       
        
        /// <summary>
        /// Recursion-desired flag
        /// </summary>
        public bool RecursionDesired { get; set; }

        /// <summary>
        /// </summary>
        private DnsResolverOptions()
        {
        }

        public static DnsResolverOptions CreateDefault()
        {
            DnsResolverOptions options = new DnsResolverOptions();

            options.ClientMessageIO = new DnsResolverMessageIO_Rfc1035Classic(5000, 5000, true);
            options.SBeltServers = CreateDefaultSBeltServers();
            options.MaxRequestCountForResolve = 150;
            options.RecursionDesired = true;
            options.Cache = new InMemoryDnsResolverCache();

            return options;
        }
        
        // public static void 

        public static ResourceRecord[] CreateDefaultSBeltServers()
        {
            var serversRecords = DnsWellKnownServers.AllRootServers.SelectMany(t => new ResourceRecord[]
           {
                new ResourceRecord() { Class = QClass.IN, Type = QType.NS, Name = "", TTL = 1000, RData = new RDataNS(t.HostName) },
                new ResourceRecord() { Class = QClass.IN, Type = QType.A, Name = t.HostName, TTL = 1000, RData = new RDataA(t.IPv4Address.ToString()) },
                new ResourceRecord() { Class = QClass.IN, Type = QType.AAAA, Name = t.HostName, TTL = 1000, RData = new RDataAAAA(t.IPv6Address.GetAddressBytes()) },
           }).ToList();

            serversRecords.AddRange(DnsWellKnownServers.DnsGoogle.AsResourceRecords);

            return serversRecords.ToArray();
        }

        /// <summary>
        /// Will set current message IO to HTTPS (DoH) RFC-8484 <see cref="ClientMessageIO"/>.
        /// Current message io will be overriden by this new configuration
        /// </summary>
        /// <param name="httpsUri"></param>
        /// <param name="method"></param>
        public void SetClientMessageIO_DoH(
            string httpsUri,
            string httpGetQueryParameterName,
            DnsResolverMessageIO_Rfc8484DoH.HttpMethod method)
        {
            ClientMessageIO = new DnsResolverMessageIO_Rfc8484DoH(httpsUri, httpGetQueryParameterName, new HttpClient(), method, new Version(2, 0));
        }

        /// <summary>
        /// Will set current message IO to class binary format (wire format) RFC-1035 <see cref="ClientMessageIO"/>.
        /// Current message io will be overriden by this new configuration
        /// </summary>
        public void SetClientMessageIO_Classic(int utcSocketReceiveTimeout = 5000, int tcpSocketReceiveTimeout = 5000, bool useTcpIfTrucated = true)
        {
            ClientMessageIO = new DnsResolverMessageIO_Rfc1035Classic(utcSocketReceiveTimeout, tcpSocketReceiveTimeout, true);
        }

        public void SetSBeltServers(ResourceRecord[] resourceRecords)
        {
            this.SBeltServers = resourceRecords;
        }
    }
}
