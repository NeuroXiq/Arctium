using Arctium.Protocol.DNS.Model;
using System.Net;

namespace Arctium.Protocol.DNS
{
    public class InMemoryDndResolverLocalData : IDndResolverLocalData
    {
        private List<CacheEntry> entries;
        static readonly ResourceRecord[] sbeltServers;
        static readonly object _lock = new object();

        static InMemoryDndResolverLocalData()
        {
            var roots = DnsRootServers.All.SelectMany(t => new ResourceRecord[]
            {
                new ResourceRecord() { Class = QClass.IN, Type = QType.NS, Name = t.HostName, TTL = 1000, RData = new RDataNS(t.HostName) },
                new ResourceRecord() { Class = QClass.IN, Type = QType.A, Name = t.HostName, TTL = 1000, RData = new RDataA(t.IPv4Address.ToString()) },
                new ResourceRecord() { Class = QClass.IN, Type = QType.AAAA, Name = t.HostName, TTL = 1000, RData = new RDataAAAA(t.IPv6Address.GetAddressBytes()) },
            }).ToList();

            roots.Add(new ResourceRecord() { Class = QClass.IN, Name = "dns.google", Type = QType.NS, RData = new RDataNS("dns.google"), TTL = 1000 });
            roots.Add(new ResourceRecord() { Class = QClass.IN, Name = "dns.google", Type = QType.A, RData = new RDataA("8.8.8.8"), TTL = 1000 });
            roots.Add(new ResourceRecord() { Class = QClass.IN, Name = "dns.google", Type = QType.NS, RData = new RDataNS("dns.google"), TTL = 1000 });
            roots.Add(new ResourceRecord() { Class = QClass.IN, Name = "dns.google", Type = QType.A, RData = new RDataA("8.8.4.4"), TTL = 1000 });

            sbeltServers = roots.ToArray();
        }

        public InMemoryDndResolverLocalData()
        {
            entries = new List<CacheEntry>();

            foreach (var sserver in sbeltServers)
            {
                entries.Add(new CacheEntry(sserver, DateTime.UtcNow, DateTimeOffset.Parse("2999-12-31")));
            }
        }

        public ResourceRecord[] SBeltServers => sbeltServers;

        public void AppendCache(ResourceRecord[] resourceRecords)
        {
            lock (_lock)
            {
                foreach (ResourceRecord record in resourceRecords)
                {
                    var existing = entries.Where(t => t.Record.Class == record.Class && t.Record.Type == record.Type && t.Record.Name == record.Name).ToArray();

                    foreach (var toRemove in existing) entries.Remove(toRemove);

                    DateTimeOffset expiration = DateTimeOffset.UtcNow.AddSeconds(record.TTL);
                    DateTimeOffset minExpiration = DateTimeOffset.UtcNow.AddMinutes(10);
                    expiration = expiration > minExpiration ? expiration : minExpiration;

                    CacheEntry newEntry = new CacheEntry(record, DateTimeOffset.UtcNow, expiration);
                    entries.Add(newEntry);
                }
            }
        }

        public bool TryGetCache(string hostName, QClass qclass, QType qtype, out ResourceRecord[] resultResourceRecords)
        {
            lock (_lock)
            {
                DateTimeOffset now = DateTimeOffset.UtcNow;
                List<CacheEntry> foundEntries = entries.Where(t =>
                        t.Record.Name == hostName
                        && t.Record.Type == qtype
                        && t.Record.Class == qclass)
                    .ToList();

                if (foundEntries.Count == 0)
                {
                    resultResourceRecords = null;
                    return false;
                }

                List<CacheEntry> expired = foundEntries.Where(t => t.ExpireOn > now).ToList();

                if (expired.Count > 0)
                {
                    foreach (CacheEntry expiredEntry in expired)
                    {
                        foundEntries.Remove(expiredEntry);
                        entries.Remove(expiredEntry);
                    }
                }

                ResourceRecord[] result = foundEntries.Select(t => t.Record).ToArray();

                resultResourceRecords = result;
                return result.Length > 0;
            }
        }

        class CacheEntry
        {
            public DateTimeOffset CreatedOn { get; set; }
            public DateTimeOffset ExpireOn { get; set; }
            public ResourceRecord Record { get; set; }

            public CacheEntry(ResourceRecord record, DateTimeOffset createOn, DateTimeOffset expireOn)
            {
                CreatedOn = createOn;
                ExpireOn = expireOn;
                Record = record;
            }

            public override string ToString() => $"{Record.Name} {Record.Type}";
        }
    }
}
