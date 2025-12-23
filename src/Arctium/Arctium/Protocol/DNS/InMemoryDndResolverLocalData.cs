using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS
{
    public class InMemoryDndResolverLocalData : IDndResolverLocalData
    {
        public IDnsResolverCache Cache { get; private set; }
        public ResourceRecord[] SBeltServers => sbeltServers;
        
        static readonly ResourceRecord[] sbeltServers;

        static InMemoryDndResolverLocalData()
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

            sbeltServers = roots.ToArray();
        }

        public InMemoryDndResolverLocalData()
        {
            Cache = new InMemoryDnsResolverCache();
        }
    }
}
