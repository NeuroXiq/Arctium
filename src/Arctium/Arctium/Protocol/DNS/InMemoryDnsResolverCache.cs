using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS
{
    public class InMemoryDnsResolverCache : IDnsResolverCache
    {
        private List<CacheEntry> entries;
        private bool neverExpire;
        static readonly object _lock = new object();

        public InMemoryDnsResolverCache(bool neverExpire = false)
        {
            entries = new List<CacheEntry>();
            this.neverExpire = neverExpire;
        }

        public void Set(ResourceRecord[] resourceRecords)
        {
            lock (_lock)
            {
                IEnumerable<CacheEntry> toRemove = entries
                    .Where(e => resourceRecords.Any(r => r.IsNameTypeClassEqual(e.Record)))
                    .ToList();

                foreach (CacheEntry remove in toRemove)
                {
                    entries.Remove(remove);
                }

                foreach (ResourceRecord record in resourceRecords)
                {
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
                List<CacheEntry> foundEntries = entries.Where(t => t.Record.IsNameTypeClassEqual(hostName, qclass, qtype)).ToList();
                List<CacheEntry> expired = foundEntries.Where(t => t.ExpireOn < now).ToList();

                if (neverExpire) expired.Clear();

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
