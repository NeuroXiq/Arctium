using Arctium.Protocol.DNS.Model;
using System.Net;

namespace Arctium.Protocol.DNS
{
    public class InMemoryDndResolverLocalData : IDndResolverLocalData
    {
        private List<CacheEntry> entries;
        static readonly IPAddress[] sbelt;
        static readonly object _lock = new object();

        static InMemoryDndResolverLocalData()
        {
            List<IPAddress> sbeltList = new List<IPAddress>();
            sbeltList.Add(IPAddress.Parse("8.8.8.8"));
            sbeltList.Add(IPAddress.Parse("8.8.4.4"));
            sbeltList.AddRange(DnsRootServers.All.Select(t => t.IPv4Address));

            sbelt = sbeltList.ToArray();
        }

        public InMemoryDndResolverLocalData()
        {
            entries = new List<CacheEntry>();
        }

        public IPAddress[] GetSBeltServers()
        {
            return sbelt;
        }

        public void SetCache(string hostName, QType qtype, QClass qclass, ResourceRecord[] resourceRecords)
        {
            lock (_lock)
            {
                entries.RemoveAll(e => e.Record.Name == hostName && e.Record.Type == qtype && e.Record.Class == qclass);

                foreach (ResourceRecord record in resourceRecords)
                {
                    CacheEntry newEntry = new CacheEntry(record, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddSeconds(record.TTL));
                    entries.Add(newEntry);
                }
            }
        }

        public bool TryGetCache(string hostName, QType qtype, QClass qclass, out ResourceRecord[] resultResourceRecords)
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

                List<CacheEntry> expired = foundEntries.Where(t => t.ExpireOn < now).ToList();

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
                return true;
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
        }
    }
}
