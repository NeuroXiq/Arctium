using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS.Protocol
{
    /// <summary>
    /// During resolving processing some records must be always cached
    /// to reuse them later in next parts of query processing.
    /// This proxy class will always store temporary cached records.
    /// without expiration. Additionaly makes a proxy for real cache.
    /// </summary>
    class TempProxyCache
    {
        private List<ResourceRecord> tempCacheRecords;
        private IDnsResolverCache realCache;

        public TempProxyCache(IDnsResolverCache realCache)
        {
            this.realCache = realCache;
            tempCacheRecords = new List<ResourceRecord>();
        }

        public bool TryGetAandAAAA(string name, QClass qclass, out ResourceRecord[] records)
        {
            List<ResourceRecord> result = new List<ResourceRecord>();
            ResourceRecord[] result1, result2;
            bool ok1, ok2;

            ok1 = TryGet(name, qclass, QType.A, out result1);
            ok2 = TryGet(name, qclass, QType.AAAA, out result2);

            if (ok1) result.AddRange(result1);
            if (ok2) result.AddRange(result2);

            if (ok1 || ok2)
            {
                records = result.ToArray();
                return true;
            }

            records = null;
            return false;
        }

        public bool TryGet(string name, QClass qclass, QType qtype, out ResourceRecord[] records)
        {
            ResourceRecord[] resolverCacheRecords;
            List<ResourceRecord> result;
            bool anyTemp, anyReal;

            result = tempCacheRecords.Where(t => t.IsNameTypeClassEqual(name, qclass, qtype)).ToList();

            anyTemp = result.Count > 0;
            anyReal = realCache.TryGet(name, qclass, qtype, out resolverCacheRecords);

            if (anyReal)
            {
                foreach (var rcRecord in resolverCacheRecords)
                {
                    // always prefere tempCache instead of realCache
                    if (!result.Any(r => r.IsNameTypeClassEqual(rcRecord)))
                    {
                        result.Add(rcRecord);
                    }
                }
            }

            if (anyReal || anyTemp)
            {
                records = result.ToArray();
                return true;
            }
            else
            {
                records = null;
                return false;
            }
        }

        public void Set(ResourceRecord[] records)
        {
            foreach (ResourceRecord record in records)
            {
                ResourceRecord[] toRemove = tempCacheRecords
                    .Where(t => t.IsNameTypeClassEqual(record))
                    .ToArray();

                foreach (ResourceRecord remove in toRemove)
                {
                    tempCacheRecords.Remove(remove);
                }

                tempCacheRecords.Add(record);
            }

            realCache.Set(records);
        }
    }
}
