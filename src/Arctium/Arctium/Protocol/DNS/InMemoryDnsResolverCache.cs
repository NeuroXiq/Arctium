using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS
{
    public class InMemoryDnsResolverCache : IDnsResolverCache
    {
        private List<CacheEntry> entries;
        static readonly object _lock = new object();

        public InMemoryDnsResolverCache()
        {
            entries = new List<CacheEntry>();
        }

        public void Set(ResourceRecord[] resourceRecords)
        {
            lock (_lock)
            {
                foreach (ResourceRecord record in resourceRecords)
                {
                    var existing = entries.Where(t => t.Record.Class == record.Class && t.Record.Type == record.Type && t.Record.Name == record.Name).ToArray();

                    // foreach (var toRemove in existing) entries.Remove(toRemove);

                    DateTimeOffset expiration = DateTimeOffset.UtcNow.AddSeconds(record.TTL);
                    DateTimeOffset minExpiration = DateTimeOffset.UtcNow.AddMinutes(10);
                    expiration = expiration > minExpiration ? expiration : minExpiration;

                    CacheEntry newEntry = new CacheEntry(record, DateTimeOffset.UtcNow, expiration);
                    entries.Add(newEntry);
                }
            }
        }

        public bool TryGet(string hostName, QClass qclass, QType qtype, out ResourceRecord[] resultResourceRecords)
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

                foreach (CacheEntry expiredEntry in expired)
                {
                    foundEntries.Remove(expiredEntry);
                    entries.Remove(expiredEntry);
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
